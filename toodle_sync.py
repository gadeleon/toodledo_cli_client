'''
Simple pull of account info
'''
import requests
import datetime
import pickle
import json
import time
import sys

account_url = 'https://api.toodledo.com/3/account/get.php?access_token='
tasks_get_url = 'https://api.toodledo.com/3/tasks/get.php?access_token='
'''
Fields you can use to filter when you get tasks:

https://api.toodledo.com/3/tasks/index.php under "Task Datatypes"

'''


def load_token(token):
	token = pickle.load( open(token, 'rb'))
	return token

def sync(token):
	token = load_token(token)
	get_account = requests.get('{}{}'.format(account_url, token['access_token']))
	#cur_task = int(get_account.text['lastedit_task'])
	return get_account.text
	

def query_tasks(token, days, completion_state='1', fields='tag,context,goal'):
	token = load_token(token)
	# Get Tasks from Monday (ie 4 days ago since we cron for friday)
	start_date = datetime.date.today() - datetime.timedelta(days=days)
	# Make it Epoch Time
	start_date = int(time.mktime(start_date.timetuple()))
	start_date = str(start_date)
	# Get ALL tasks from start_date'
	# Comp codes -- 1 == completed, 0 == incomplete, -1 == both
	get_tasks = requests.get('{}{}&after={}&comp={}&fields={}'.format(tasks_get_url, token['access_token'], start_date, completion_state, fields))
	pickle.dump(get_tasks.text, open('tasks_queried.pkl', 'wb'))
	return get_tasks.text

def parse_to_json(response):
	data = pickle.load(open(response, 'rb'))
	return json.loads(data)

def arrange_date(epoch_time):
	completion = time.strftime('%A, %b %d, %Y', time.gmtime(epoch_time))
	return completion

def display_tasks(task_dump, context_pickle, days=4):
	task_dump = parse_to_json(task_dump)
	contexts = make_context_hash(context_pickle)
	start_date = datetime.date.today() - datetime.timedelta(days=days)
	start_date = datetime.date.strftime(start_date, '%A, %b %d, %Y')
	end_date = datetime.date.today()
	end_date = datetime.date.strftime(end_date, '%A, %b %d, %Y')
	print 'Tasks Created between {} and {}.'.format(start_date, end_date)
	print 'Total Tasks: ', task_dump[0]['total']
	for i in range(len(task_dump)):
		#print task_dump[i]
		# 	print contexts
		if 'completed' in task_dump[i]:
			if task_dump[i]['completed'] == 0:
				print 'Incomplete Task: {}'.format(task_dump[i]['title'])
			elif contexts[task_dump[i]['context']] != 'Standing Meeting':
				comp_date = arrange_date(task_dump[i]['completed'])
				print 'Completed Task : {}, Completed {}'.format(task_dump[i]['title'], comp_date)
		else:
			pass
	#test = display_tasks('tasks_queried.pkl', 4)
def format_task(task):
	'''
	Take a dictionary formatted task from display tasks and print it
	out to something human readable.
	'''
	comp_date = arrange_date(task['completed'])
	print 'Completed Task : {}, Completed {}'.format(task['title'], comp_date)

def get_completed_tasks():
	query = query_tasks('auth_token.pkl', 4, '1')
	return query

def get_incomplete_tasks():
	query = query_tasks('auth_token.pkl', 4, '0')
	return query

def get_all_tasks():
	query = query_tasks('auth_token.pkl', 4, '-1')
	return query

def get_defined_list_ids(token, defined_list):
	valid_lists = ['goals', 'contexts']
	if defined_list.lower() not in valid_lists:
		print 'Not a valid user defined list, exiting...'
		sys.exit(2)
	token = load_token(token)
	query = requests.get('http://api.toodledo.com/3/{}/get.php?access_token={}'.format(defined_list, token['access_token']))
	pickle.dump(query.text, open('{}_queried.pkl'.format(defined_list), 'wb'))
	return query.text

def make_context_hash(defined_list_pickle):
	contexts = pickle.load( open(defined_list_pickle, 'rb'))
	contexts = json.loads(contexts)
	out = {}
	for i in range(len(contexts)):
		out[contexts[i]['id']] = contexts[i]['name']
	return out

#tasks = get_completed_tasks()
#print tasks


if __name__ == '__main__':
	tdump = display_tasks('tasks_queried.pkl', 4)

