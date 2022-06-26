# -*- coding: utf-8 -*-
# @Author: Cristi Cretan
# @Date:   2022-06-10 14:53:11
# @Last Modified by:   Cristi Cretan
# @Last Modified time: 2022-06-25 16:12:37

from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, MetaData, Table
from datetime import datetime

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
		all_events = db.query(events).all()
		print(all_events)
		all_dates = [datetime.utcfromtimestamp(x[3]).strftime("%Y-%m-%d") for x in all_events]
		all_times = [datetime.utcfromtimestamp(x[4]).strftime("%H") for x in all_events]
		print(all_times)
		times = [str(x[0]) + " " + str(x[1]) for x in zip(all_dates, all_times)]
		print(times)
		return render_template('basic_table.html', title='Events Table', events=all_events)

app.run(host='127.0.0.1', port=5000)
