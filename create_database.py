from flask import Flask
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
import requests
from os import remove

#Base URL for get requests
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

#Initializing the API and database structure
app = Flask(__name__)
api = Api(app)

#before initializing the database as an SQLAlchemy object, delete the old one
#remove('.\\database.db')

#For now, the database will be kept in a local file. This may be changed later
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

#Defining the fields we want to have in the CVE database
class CVEModel(db.Model):
	entry_num		= db.Column(db.Integer, primary_key = True)
	id 				= db.Column(db.String(15), nullable = False)
	srcID 			= db.Column(db.String(25), nullable = False)
	published 		= db.Column(db.String(25), nullable = False)
	modified 		= db.Column(db.String(25), nullable = False)
	vulnStatus 		= db.Column(db.String(10), nullable = False)
	cveTags 		= db.Column(db.TEXT)
	descriptions 	= db.Column(db.TEXT)
	metrics			= db.Column(db.TEXT)
	weaknesses		= db.Column(db.TEXT)
	references		= db.Column(db.TEXT)

#Creating the table inside the database for modifications
db.create_all()	

#This module is meant to be called by another program, hence why this is a function and not main
def recreateDatabase(BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0/", results_pp: int = 20):
	start_ind = 0
	#Start by querying the first page of elements, the number of entries is given by a parameter in the funciton
	#with a default value of 20. 
	response = requests.get(BASE_URL + f"?resultsPerPage={results_pp}&startIndex={start_ind}")
	data = response.json()
	#Extract the total number of entries in the database
	total_elements = int(data["totalResults"])
	
	for counter in range(total_elements):
		#This statement will trigger every time we need to query the database again
		if(counter % results_pp == 0 and counter > 0):
			response = requests.get(BASE_URL + f"?resultsPerPage={results_pp}&startIndex={start_ind}")
			data = response.json()

		#From the conversion to a dictionary from the .json() method, we only care about the key 'vulnerabilities'
		cve_data = data['vulnerabilities'][counter % results_pp]['cve']
		#After getting the data for the specific entry, add it to the DB. There is no duplicate filtering yet, and 
		#the unique identifier I used is the entry number in the page.
		cve = CVEModel(
			entry_num	= counter,
			id 			= cve_data['id'],
			srcID 		= cve_data['sourceIdentifier'],
			published 	= cve_data['published'],
			modified 	= cve_data['lastModified'],
			vulnStatus 	= cve_data['vulnStatus'],
			cveTags 	= str(cve_data['cveTags']),
			descriptions= str(cve_data['descriptions']),
			metrics		= str(cve_data['metrics']),
			weaknesses	= str(cve_data['weaknesses']),
			references	= str(cve_data['references']))
		db.session.add(cve)
		db.session.commit()


#The call to the method in case the file is run by itself
recreateDatabase()
