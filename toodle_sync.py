'''
Simple pull of account info
'''
import requests
import datetime
import pickle
import json
import time

account_url = 'https://api.toodledo.com/3/account/get.php?access_token='
tasks_get_url = 'https://api.toodledo.com/3/tasks/get.php?access_token='

def load_token(token):
	token = pickle.load( open(token, 'rb'))
	return token

def sync(token):
	token = load_token(token)
	get_account = requests.get('{}{}'.format(account_url, token['access_token']))
	#cur_task = int(get_account.text['lastedit_task'])
	return get_account.text
	

def query_tasks(token):
	token = load_token(token)
	# Get Tasks from Monday (ie 4 days ago since we cron for friday)
	start_date = datetime.date.today() - datetime.timedelta(days=4)
	# Make it Epoch Time
	start_date = int(time.mktime(start_date.timetuple()))
	start_date = str(start_date)
	# Get ALL tasks from start_date'
	# Comp codes -- 1 == completed, 0 == incomplete, -1 == both
	get_tasks = requests.get('{}{}&after={}&comp={}'.format(tasks_get_url, token['access_token'], start_date, '-1'))
	pickle.dump(get_tasks.text, open('tasks_queried.pkl', 'wb'))
	return get_tasks.text

def parse_to_json(response):
	data = pickle.load(open(response, 'rb'))
	return json.loads(data)

def completion_date(epoch_time):
	completion = time.strftime('%A, %b %d, %Y', time.gmtime(epoch_time))
	return completion

#query = query_tasks('auth_token.pkl')
response_data = parse_to_json('tasks_queried.pkl')
print 'Total Tasks: ', response_data[0]['total']
for i in range(len(response_data)):
	if 'completed' in response_data[i]:
		if response_data[i]['completed'] == 0:
			print 'Incomplete Task: {}'.format(response_data[i]['title'])
		else:
			comp_date = completion_date(response_data[i]['completed'])
			print 'Completed Task : {}, Completed {}'.format(response_data[i]['title'], comp_date)
	else:
		pass
