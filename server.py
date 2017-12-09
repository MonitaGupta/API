from flask import Flask, request, Response
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from json import dumps
from flask_jsonpify import jsonify
from flask import Flask, render_template, make_response
import sqlite3
from flask import g
from flask import Flask, flash, redirect, render_template, request, session, abort
import os
from passlib.apps import custom_app_context as pwd_context
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

app = Flask(__name__)
api = Api(app)

def connect_db():
    return sqlite3.connect('sqllite3/project_inmar.db')

@app.before_request
def before_request():
    g.db = connect_db()

@app.after_request
def after_request(response):
    g.db.close()
    return response	
    
def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv
    
def hash_password(password):
    return pwd_context.encrypt(password)

def verify_password1(password, password_hash):
    return pwd_context.verify(password, password_hash)
    
@auth.verify_password
def verify_password(email, pwd1):
    if email is None or pwd1 is None:
        return False # missing arguments

    result = query_db('SELECT count(*) from user where email=?;', [email])
    if [d['count(*)'] for d in result] == [0]:
        return False        
        
    result = query_db('SELECT pass_hash from user where email=?', [email])

    verified = verify_password1 (pwd1, [d['pass_hash'] for d in result][0])
    
    if not verified:
        return False
    return True    

@app.route('/api/v1/users/<email>/<pwd1>/<pwd2>', methods = ['POST'])
def new_user(email, pwd1, pwd2):
    if email is None or pwd1 is None or pwd2 is None:
        abort(400) # missing arguments
        
    if pwd1 != pwd2:
        return jsonify('Password do not match.'), 403
    
    result = query_db('SELECT count(*) from user where email=?;', [email])
    if [d['count(*)'] for d in result] != [0]:
        return jsonify('User already exist'), 403
        
    pass_hash = hash_password(pwd1)
    c=g.db.cursor()
    c.execute('Insert into user values(?, ?);', [email, pass_hash])	
    g.db.commit()

    result = query_db('SELECT * from user where email=?;', [email])
    
    return jsonify(result), 200, {'Location': '/welcome'}

@app.route('/api/v1/users/signin/<email>/<pwd1>', methods = ['POST'])
def user_signin(email, pwd1):
    if email is None or pwd1 is None:
        abort(400) # missing arguments

    result = query_db('SELECT count(*) from user where email=?;', [email])
    if [d['count(*)'] for d in result] == [0]:
        return jsonify('User does not exist'), 401        
        
    result = query_db('SELECT pass_hash from user where email=?', [email])

    verified = verify_password1 (pwd1, [d['pass_hash'] for d in result][0])
    
    if not verified:
        return jsonify('Wrong password.'), 401

    result = query_db('SELECT * from user where email=?;', [email])
    
    return jsonify(result), 200, {'Location': '/welcome'}    
	
@app.route('/')
def main():
    resp = make_response(render_template('index.html'))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp
    
@app.route('/welcome')
def welcome():
    resp = make_response(render_template('welcome.html'))
    return resp    
	
@app.route('/showSignUp')
def showSignUp():
    return render_template('signup.html')
    
@app.route('/showSignIn')
def showSignIp():
    return render_template('sign_in.html')

@app.route('/api/v1/location')
@auth.login_required
def location():
    result = query_db('SELECT * FROM location;')
    return jsonify(result)

@app.route('/api/v1/location/<loc_id>/department')
@auth.login_required
def department(loc_id):
    result = query_db('SELECT * FROM department where loc_id=?;', [loc_id])
    return jsonify(result)

@app.route('/api/v1/location/<loc_id>/department/<dept_id>/category')
@auth.login_required
def category(loc_id, dept_id):
    result = query_db('SELECT * FROM category where dept_id=?;', [dept_id])
    return jsonify(result)

@app.route('/api/v1/location/<loc_id>/department/<dept_id>/category/<cat_id>/subcategory')
@auth.login_required
def subcategory(loc_id, dept_id, cat_id):
    result = query_db('SELECT * FROM subcategory where cat_id=?;', [cat_id])
    return jsonify(result)

@app.route('/api/v1/<loc_name>/<dept_name>/<cat_name>/<subcategory_name>/get_sku')
@auth.login_required
def sku(loc_name, dept_name, cat_name, subcategory_name):
    result = query_db('SELECT s.id, s.sku_id FROM sku s join subcategory sc on s.subcategory_id = sc.id where sc.name=?;', [subcategory_name])
    return jsonify(result)		

@app.route('/api/v1/<loc_id>/<dept_id>/<cat_id>/<subcategory_id>/get_sku_by_ids')
@auth.login_required
def sku_by_ids(loc_id, dept_id, cat_id, subcategory_id):
    result = query_db('SELECT s.id, s.sku_id FROM sku s where s.subcategory_id=?;', [subcategory_id])
    return jsonify(result)
	
@app.route('/api/v1/location/<loc_name>', methods=['POST', 'PUT', 'DELETE'])
@auth.login_required
def write_location(loc_name):
    if request.method == 'POST' or request.method == 'PUT':
        result = query_db('SELECT count(*) from location where name=?;', [loc_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('Duplicate entry.'), 403
        c=g.db.cursor()
        c.execute('Insert into location(name) values(?);', [loc_name])	
        g.db.commit()
        result = query_db('SELECT id, name from location where name=?;', [loc_name])
        return jsonify(result), 201
		
    else:
        result = query_db('SELECT count(*) from location where name=?;', [loc_name])
        if [d['count(*)'] for d in result] == [0]:
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from department where loc_id=(select id from location where name=?);', [loc_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('This location is linked to one or more departments. Cannot delete'), 403
            
        c=g.db.cursor()
        c.execute('Delete from location where name = ?;', [loc_name])	
        g.db.commit()
        return jsonify('Entry Deleted'), 200	

@app.route('/api/v1/location/<loc_name>/department/<dept_name>', methods=['POST', 'PUT', 'DELETE'])        
@auth.login_required
def write_department(loc_name, dept_name):
    if request.method == 'POST' or request.method == 'PUT':
        result = query_db('SELECT count(*) from department where name=?;', [dept_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('Duplicate entry.'), 403
        
        result = query_db('SELECT count(*) from location where name=?;', [loc_name])
        if [d['count(*)'] for d in result] == [0]:
            return jsonify('Location does not exist. Cannot Create'), 403
        
        c=g.db.cursor()
        c.execute('Insert into department(name, loc_id) select ?, id from location where name=?;', [dept_name, loc_name])	
        g.db.commit()
        result = query_db('SELECT d.id as department_id, d.name as department_name, l.name as location_name from department d \
                           join location l on d.loc_id=l.id where d.name=?;', [dept_name])
        return jsonify(result), 201
		
    else:
        result = query_db('SELECT count(*) from department where name=?;', [dept_name])
        if [d['count(*)'] for d in result] == [0]:
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from category where dept_id=(select id from department where name=?);', [dept_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('This department is linked to one or more category. Cannot delete'), 403            
            
        c=g.db.cursor()
        c.execute('Delete from department where name = ?;', [dept_name])	
        g.db.commit()
        return jsonify('Entry Deleted'), 200	
   
@app.route('/api/v1/department/<dept_name>/category/<cat_name>', methods=['POST', 'PUT', 'DELETE'])        
@auth.login_required
def write_category(dept_name, cat_name):
    if request.method == 'POST' or request.method == 'PUT':
        result = query_db('SELECT count(*) from category where name=?;', [cat_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('Duplicate entry.'), 403
        
        result = query_db('SELECT count(*) from department where name=?;', [dept_name])
        if [d['count(*)'] for d in result] == [0]:
            return jsonify('Department does not exist. Cannot Create'), 403
        
        c=g.db.cursor()
        c.execute('Insert into category(name, dept_id) select ?, id from department where name=?;', [cat_name, dept_name])	
        g.db.commit()
        result = query_db('SELECT c.id as category_id, c.name as category_name, d.name as department_name from department d \
                           join category c on d.id=c.dept_id where c.name=?;', [cat_name])
        return jsonify(result), 201
		
    else:
        result = query_db('SELECT count(*) from category where name=?;', [cat_name])
        if [d['count(*)'] for d in result] == [0]:
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from subcategory where cat_id=(select id from category where name=?);', [cat_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('This category is linked to one or more subcategory. Cannot delete'), 403            
            
        c=g.db.cursor()
        c.execute('Delete from category where name = ?;', [cat_name])	
        g.db.commit()
        return jsonify('Entry Deleted'), 200
        
@app.route('/api/v1/category/<cat_name>/subcategory/<subcat_name>', methods=['POST', 'PUT', 'DELETE'])        
@auth.login_required
def write_subcategory(cat_name, subcat_name):
    if request.method == 'POST' or request.method == 'PUT':
        result = query_db('SELECT count(*) from subcategory where name=?;', [subcat_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('Duplicate entry.'), 403
        
        result = query_db('SELECT count(*) from category where name=?;', [cat_name])
        if [d['count(*)'] for d in result] == [0]:
            return jsonify('Category does not exist. Cannot Create'), 403
        
        c=g.db.cursor()
        c.execute('Insert into subcategory(name, cat_id) select ?, id from category where name=?;', [subcat_name, cat_name])	
        g.db.commit()
        result = query_db('SELECT sc.id as subcategory_id, sc.name as subcategory_name, c.name as category_name from category c \
                           join subcategory sc on c.id=sc.cat_id where sc.name=?;', [subcat_name])
        return jsonify(result), 201
		
    else:
        result = query_db('SELECT count(*) from subcategory where name=?;', [subcat_name])
        if [d['count(*)'] for d in result] == [0]:
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from sku where subcategory_id=(select id from subcategory where name=?);', [subcat_name])
        if [d['count(*)'] for d in result] != [0]:
            return jsonify('This subcategory is linked to one or more skus. Cannot delete'), 403            
            
        c=g.db.cursor()
        c.execute('Delete from subcategory where name = ?;', [subcat_name])	
        g.db.commit()
        return jsonify('Entry Deleted'), 200        

@app.route('/api/v1/location/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_location(old_name, new_name):
    result = query_db('SELECT count(*) from location where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update location set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    return jsonify('Entry Updated'), 200

@app.route('/api/v1/department/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_dept(old_name, new_name):
    result = query_db('SELECT count(*) from department where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update department set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    return jsonify('Entry Updated'), 200
    
@app.route('/api/v1/category/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_cat(old_name, new_name):
    result = query_db('SELECT count(*) from category where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update category set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    return jsonify('Entry Updated'), 200

@app.route('/api/v1/subcategory/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_subcat(old_name, new_name):
    result = query_db('SELECT count(*) from subcategory where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update subcategory set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    return jsonify('Entry Updated'), 200    
    
if __name__ == '__main__':
     app.run(port='5002')
     