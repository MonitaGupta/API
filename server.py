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
import logging
from optparse import OptionParser
import time
from apscheduler.schedulers.background import BackgroundScheduler
import csv
from collections import defaultdict

parser = OptionParser()
parser.add_option("-l", "--log-level", dest="loglevel", default="INFO",
                  help="set log level")

(options, args) = parser.parse_args()

auth = HTTPBasicAuth()

app = Flask(__name__)
api = Api(app)

def mkdir_p(path):
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise     

logger = logging.getLogger(__name__)        
mkdir_p('log')        
current_datetime = time.strftime('%Y-%m-%d-HOUR-%H.log')   
handler = logging.FileHandler('log/'+current_datetime, mode='a')   
        
def log_setup():
    logger.setLevel(options.loglevel.upper()) 

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)

log_setup()
    
def create_new_log_file():
    handler.close()
    current_datetime = time.strftime('%Y-%m-%d-HOUR-%H.log')   
    logging.FileHandler('log/'+current_datetime, mode='a')
    
    list_of_files = os.listdir('log')    
    full_path = ["log/{0}".format(x) for x in list_of_files]
    
    if len([name for name in list_of_files]) == 25:
        oldest_file = min(full_path, key=os.path.getctime)
        os.remove(oldest_file)    

sched = BackgroundScheduler() 
sched.add_job(create_new_log_file, 'cron', minute=0)
sched.start()

def connect_db():
    logger.info('Connecting to database')
    return sqlite3.connect('sqllite3/project_inmar.db') 

@app.before_request
def before_request(): 
    endpoint = '/'
    if not request.endpoint is None:
        endpoint=request.endpoint
    logger.info("API endpoint:"+endpoint)
    g.db = connect_db()
    logger.info('Connection established')

@app.after_request
def after_request(response):
    g.db.close()
    logger.info('Closing database connection')
    logger.info('Response: %s', response)
    #logger.debug('Response: %s', response.get_data())
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
        logger.info("UserName or Password or both missing")
        return False # missing arguments

    result = query_db('SELECT count(*) from user where email=?;', [email])
    if [d['count(*)'] for d in result] == [0]:
        logger.info("UserName doesn't exist")
        return False        
        
    result = query_db('SELECT pass_hash from user where email=?', [email])
    verified = verify_password1 (pwd1, [d['pass_hash'] for d in result][0])
    if not verified:
        logger.info("Wrong password")
        return False
    logger.info("Password matched")
    return True    

@app.route('/api/v1/back_welcome')
def back_welcome():
    return jsonify('Back'), 200, {'Location': '/welcome'}
    
@app.route('/api/v1/users/<email>/<pwd1>/<pwd2>', methods = ['POST'])
def new_user(email, pwd1, pwd2):
    if email is None or pwd1 is None or pwd2 is None:
        logger.error('UserName or Password or Retye-Password missing.')
        abort(400) # missing arguments
        
    if pwd1 != pwd2:
        logger.error('Password and Retye-Password does not match.')
        return jsonify('Password do not match'), 403
    
    result = query_db('SELECT count(*) from user where email=?;', [email])
    if [d['count(*)'] for d in result] != [0]:
        logger.error('User already exist')
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
        logger.error('UserName or Password or both missing.')
        abort(400) # missing arguments

    result = query_db('SELECT count(*) from user where email=?;', [email])
    if [d['count(*)'] for d in result] == [0]:
        logger.error('User does not exist')
        return jsonify('User does not exist'), 401        
        
    result = query_db('SELECT pass_hash from user where email=?', [email])

    verified = verify_password1 (pwd1, [d['pass_hash'] for d in result][0])
    
    if not verified:
        logger.error('Wrong password')
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

def ctree():
    return defaultdict(ctree)


def build_leaf(name, leaf):
    res = {"name": name}

    # add children node if the leaf actually has any children
    if len(leaf.keys()) > 0:
        res["children"] = [build_leaf(k, v) for k, v in leaf.items()]

    return res

@app.route('/api/v1/showjsontree')
@auth.login_required
def showjsontree():    
    return jsonify('Tree'), 200, {'Location': '/showtree'}
    
@app.route('/showtree')
def showTree():
    resp = make_response(render_template('showtree.html'))
    
    return resp    
    
@app.route('/api/v1/metadata')
@auth.login_required
def metadata():
    mkdir_p('csv')    
        
    outfile = open('csv/output.csv', 'w')
    outcsv = csv.writer(outfile)

    cursor = g.db.execute('SELECT "Metadata", l.name, d.name, c.name, s.name  FROM location l join department d on l.id = d.loc_id join category c \
                           on d.id = c.dept_id join subcategory s on c.id = s.cat_id;')


    outcsv.writerows(cursor)
    outfile.close()        

    tree = ctree()
    # NOTE: you need to have test.csv file as neighbor to this file
    with open('csv/output.csv') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for rid, row in enumerate(reader):
            if row:
                # usage of python magic to construct dynamic tree structure and
                # basically grouping csv values under their parents
                leaf = tree[row[0]]
                for cid in range(1, len(row)):
                    leaf = leaf[row[cid]]

    # building a custom tree structure
    res = []
    for name, leaf in tree.items():
        res.append(build_leaf(name, leaf))
    
    return jsonify(res)    

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
            logger.error('Duplicate entry')
            return jsonify('Duplicate entry.'), 403
        c=g.db.cursor()
        c.execute('Insert into location(name) values(?);', [loc_name])	
        g.db.commit()
        result = query_db('SELECT id, name from location where name=?;', [loc_name])
        return jsonify(result), 201
		
    else:
        result = query_db('SELECT count(*) from location where name=?;', [loc_name])
        if [d['count(*)'] for d in result] == [0]:
            logger.error('Entry Does Not Exist')
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from department where loc_id=(select id from location where name=?);', [loc_name])
        if [d['count(*)'] for d in result] != [0]:
            logger.error('This location is linked to one or more departments. Cannot delete')
            return jsonify('This location is linked to one or more departments. Cannot delete'), 403
            
        c=g.db.cursor()
        c.execute('Delete from location where name = ?;', [loc_name])	
        g.db.commit()
        logger.error('Entry Deleted')
        return jsonify('Entry Deleted'), 200	

@app.route('/api/v1/location/<loc_name>/department/<dept_name>', methods=['POST', 'PUT', 'DELETE'])        
@auth.login_required
def write_department(loc_name, dept_name):
    if request.method == 'POST' or request.method == 'PUT':
        result = query_db('SELECT count(*) from department where name=?;', [dept_name])
        if [d['count(*)'] for d in result] != [0]:
            logger.error('Duplicate entry.')
            return jsonify('Duplicate entry.'), 403
        
        result = query_db('SELECT count(*) from location where name=?;', [loc_name])
        if [d['count(*)'] for d in result] == [0]:
            logger.error('Location does not exist. Cannot Create')
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
            logger.error('Entry Does Not Exist')
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from category where dept_id=(select id from department where name=?);', [dept_name])
        if [d['count(*)'] for d in result] != [0]:
            logger.error('This department is linked to one or more category. Cannot delete')
            return jsonify('This department is linked to one or more category. Cannot delete'), 403            
            
        c=g.db.cursor()
        c.execute('Delete from department where name = ?;', [dept_name])	
        g.db.commit()
        logger.info('Entry Deleted')
        return jsonify('Entry Deleted'), 200	
   
@app.route('/api/v1/department/<dept_name>/category/<cat_name>', methods=['POST', 'PUT', 'DELETE'])        
@auth.login_required
def write_category(dept_name, cat_name):
    if request.method == 'POST' or request.method == 'PUT':
        result = query_db('SELECT count(*) from category where name=?;', [cat_name])
        if [d['count(*)'] for d in result] != [0]:
            logger.error('Duplicate Entry')
            return jsonify('Duplicate entry.'), 403
        
        result = query_db('SELECT count(*) from department where name=?;', [dept_name])
        if [d['count(*)'] for d in result] == [0]:
            logger.error('Department does not exist. Cannot Create')
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
            logger.error('Entry Does Not Exist')
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from subcategory where cat_id=(select id from category where name=?);', [cat_name])
        if [d['count(*)'] for d in result] != [0]:
            logger.error('This category is linked to one or more subcategory. Cannot delete')
            return jsonify('This category is linked to one or more subcategory. Cannot delete'), 403            
            
        c=g.db.cursor()
        c.execute('Delete from category where name = ?;', [cat_name])	
        g.db.commit()
        logger.info('Entry Deleted')
        return jsonify('Entry Deleted'), 200
        
@app.route('/api/v1/category/<cat_name>/subcategory/<subcat_name>', methods=['POST', 'PUT', 'DELETE'])        
@auth.login_required
def write_subcategory(cat_name, subcat_name):
    if request.method == 'POST' or request.method == 'PUT':
        result = query_db('SELECT count(*) from subcategory where name=?;', [subcat_name])
        if [d['count(*)'] for d in result] != [0]:
            logger.error('Duplicate Entry')
            return jsonify('Duplicate entry.'), 403
        
        result = query_db('SELECT count(*) from category where name=?;', [cat_name])
        if [d['count(*)'] for d in result] == [0]:
            logger.error('Category does not exist. Cannot Create')
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
            logger.error('Entry Does Not Exist.')
            return jsonify('Entry Does Not Exist.'), 403
            
        result = query_db('SELECT count(*) from sku where subcategory_id=(select id from subcategory where name=?);', [subcat_name])
        if [d['count(*)'] for d in result] != [0]:
            logger.error('This subcategory is linked to one or more skus. Cannot delete')
            return jsonify('This subcategory is linked to one or more skus. Cannot delete'), 403            
            
        c=g.db.cursor()
        c.execute('Delete from subcategory where name = ?;', [subcat_name])	
        g.db.commit()
        logger.info('Entry Deleted')
        return jsonify('Entry Deleted'), 200        

@app.route('/api/v1/location/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_location(old_name, new_name):
    result = query_db('SELECT count(*) from location where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        logger.error('Entry Does Not Exist.')
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update location set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    logger.info('Entry Updated')
    return jsonify('Entry Updated'), 200

@app.route('/api/v1/department/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_dept(old_name, new_name):
    result = query_db('SELECT count(*) from department where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        logger.error('Entry Does Not Exist')
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update department set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    logger.info('Entry Updated')
    return jsonify('Entry Updated'), 200
    
@app.route('/api/v1/category/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_cat(old_name, new_name):
    result = query_db('SELECT count(*) from category where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        logger.error('Entry Does Not Exist')
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update category set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    logger.info('Entry Updated')
    return jsonify('Entry Updated'), 200

@app.route('/api/v1/subcategory/<old_name>/<new_name>', methods=['PUT'])
@auth.login_required
def update_subcat(old_name, new_name):
    result = query_db('SELECT count(*) from subcategory where name=?;', [old_name])
    if [d['count(*)'] for d in result] == [0]:
        logger.error('Entry Does Not Exist.')
        return jsonify('Entry Does Not Exist.'), 403
            
    c=g.db.cursor()
    c.execute('Update subcategory set name=? where name = ?;', [new_name, old_name])	
    g.db.commit()
    logger.info('Entry Updated')
    return jsonify('Entry Updated'), 200    
    
if __name__ == '__main__':
     app.run(port=5002)
     