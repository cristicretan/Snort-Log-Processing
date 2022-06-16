# -*- coding: utf-8 -*-
# @Author: Cristi Cretan
# @Date:   2022-06-10 14:53:11
# @Last Modified by:   Cristi Cretan
# @Last Modified time: 2022-06-16 13:31:11

from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, MetaData, Table

app = Flask(__name__, template_folder='templates')

user = 'root'
password = '11jk13unQ1$'
host = 'localhost'
port = 3306
database = 'snortdb'

engine = create_engine("mysql://{0}:{1}@{2}:{3}/{4}".format(user, password, host, port, database))
eventsmeta = MetaData(engine)
events = Table('events', eventsmeta, autoload=True)
DBSession = sessionmaker(bind=engine)
db = DBSession()


@app.route('/', methods = ['GET'])
def execute():
	if request.method == 'GET':
		events_data = db.query(events)
		return render_template('basic_table.html', title='Events Table', events=events_data)

app.run(host='localhost', port=5000)
