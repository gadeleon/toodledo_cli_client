# -*- coding: utf-8 -*-'

'''
Way to interact with toodledo in a class
'''

import sys
import json
import time
import pickle
import urllib2
import argparse
import datetime

from getpass import getpass
from urllib import quote_plus
from pprint import pprint


import requests
import requests.auth

from requests_oauthlib import OAuth2Session


class ToodleDoAuthCLI(object):
    '''
    Class to interact with Toodledo authorization/token creation.
    '''
    def __init__(self):
        self.account_url = 'https://api.toodledo.com/3/account/get.php?access_token={}'
        self.tasks_url = 'https://api.toodledo.com/3/tasks/get.php?access_token={}'
        self.authorization_base_url = 'https://api.toodledo.com/3/account/authorize.php'
        self.token_url = 'https://api.toodledo.com/3/account/token.php'
        self.code_url = '/3/account/authorize.php?response_type=code&client_id={}&scope={}&state={}'
        self._load_app_details('app_details.pkl')

    def _load_app_details(self, app_details_pickle):
        '''
        Takes pickled hash with application details and return the attributes 
        '''
        app = pickle.load(open(app_details_pickle, 'rb'))
        self.client_id = app['client_id']
        self.client_secret = app['client_secret']
        self.redirect_uri = app['redirect_uri']

    def _auth_client(self):
        '''
        Take a pickled dict with app details and create an auth. 
        Pickled hash must be done manually.
        '''
        client_auth = requests.auth.HTTPBasicAuth(self.client_id, 
            self.client_secret)
        return client_auth

    def _gen_scope(self, *args):
        '''
        Set the scope for requests. Often 'basic tasks write' is all that's
        needed.
        Old scope variable: scope = ['basic','tasks', 'write']
        '''
        out = []
        for i in args:
            out.append(i)
        return out

    def _get_auth_code(self):
        '''
        1. Generate auth url
        2. Get request to auth url
        3. Read Response
        4. Post to response
        5. Print redirect headers
        '''
        scope = self._gen_scope('basic tasks write')
        toodle = OAuth2Session(self.client_id, 
            scope=scope)
        print toodle.scope
        authorization_url, state = toodle.authorization_url(self.authorization_base_url)
        print 'Visiting\n',authorization_url
        s = requests.Session()
        response = s.get(authorization_url)
        print response.status_code
        data = {
            'scope':scope,
            'response_type':'code',
            'client_id':self.client_id,
            'state':state,
            'playground':'0',
            'email':raw_input('Email: '),
            'pass':getpass('Pass: '),
            'authorized':'Sign In'
        }
        # The connection will fail because it goes to local host. We want to
        # Parse the URL and grab the code because it's been generated at this point
        try:
            r2 = s.post(authorization_url, data=data)
            print r2.url, r2.status_code
        except requests.ConnectionError as err:
            code = str(err).split('?')
            code = code[1].split('&')
            code = code[0].split('=')[1]
        return code, state

    def get_token(self):
        '''
        Sends Toodledo the necessary POST to generate an auth token after getting 
        the state and code from _get_auth_code().

        get_token() stores the full token as a pickle file so it can be loaded later
        or used to refresh the token.
        '''
        code, state = self._get_auth_code()
        client_auth = self._auth_client()
        post_data = {
            'grant_type':'authorization_code',
            'code':code,
            'redirect_uri':self.redirect_uri,
            'state':state,
            'device':'terminal'
        }
        response = requests.post(self.token_url, auth=client_auth, data = post_data)
        full_token = response.json()
        pickle.dump(full_token, open('auth_token.pkl', 'wb'))
        print 'Created token {}'.format(full_token['access_token'])

    def refresh(self):
        '''
        Loads the pickled auth token and makes the necessary POST request to 
        Toodledo in order to refresh the token. It then pickles the new token.
        '''
        client_auth = self._auth_client() 
        full_token = pickle.load( open('auth_token.pkl', 'rb'))
        post_data = {
            'grant_type':'refresh_token',
            'refresh_token':full_token['refresh_token'],
            'device':'terminal'
        }
        response = requests.post(self.token_url, auth=client_auth, data = post_data)
        full_token = response.json()
        pickle.dump(full_token, open('auth_token.pkl', 'wb'))
        print 'Refreshed Token {}'.format(full_token['refresh_token'])

class ToodleDoCLI():
    '''
    Class to interact with Toodledo.
    '''
    def __init__(self, token):
        self.token = self._load_token(token)['access_token']
        self.account_url = 'https://api.toodledo.com/3/account/get.php?access_token='
        self.tasks_get_url = 'https://api.toodledo.com/3/tasks/get.php?access_token='
        self.context_url = 'https://api.toodledo.com/3/contexts/get.php?access_token='
        self.folder_url = 'http://api.toodledo.com/3/folders/get.php?access_token='
        self.goal_url = 'http://api.toodledo.com/3/goals/get.php?access_token='
        self.location_url ='http://api.toodledo.com/3/locations/get.php?access_token='
        self.user_defined_hash_url = {
                                    'context' : self.context_url,
                                    'folder' : self.folder_url,
                                    'goal' : self.goal_url,
                                    'location' : self.location_url
                                    }
        self.user_defined_lists = {}
        self.valid_params = ['before', 'after', 'comp', 'id', 'start', 'num',
                            'fields']
        self.valid_fields = ['folder', 'context', 'goal', 'location', 'tag', 
                            'startdate', 'duedate', 'duedatemod', 'starttime', 
                            'duetime', 'remind', 'repeat', 'status', 'star', 
                            'priority', 'length', 'timer', 'added', 'note', 
                            'parent', 'children', 'order', 'meta', 'previous', 
                            'attachment', 'shared', 'addedby', 'via', 
                            'attachments']
        self.time_params = ['after', 'before']

    def __str__(self):
        print self.json_tasks

    def _load_token(self, token):
        self.token = pickle.load( open(token, 'rb'))
        return self.token

    def _is_valid_field_list(self, fields):
        '''
        Exits if user puts in field that doesn't exist. 
        Reference: http://api.toodledo.com/3/tasks/index.php
        '''
        for i in fields:
            if i not in self.valid_fields:
                print '"{}"" is not a valid field. Check for spelling or '\
                'accidental pluralization.'.format(i)
                return False
        return True


    def _get_user_defined_lists(self, udls):
        '''
        Retrieves and stores the user defined lists requested from a task sync

        NOTE: The lists are essentially hashes in [{'name':'id'}] format.
        '''
        for i in udls:
            i = i.lower()
            if i in self.user_defined_hash_url:
                self.user_defined_lists[i] = requests.get('{}{}'\
                    .format(self.user_defined_hash_url[i], self.token))
                self.user_defined_lists[i] = json.loads(self.user_defined_lists[i].text)

    def _form_GMT_unix_time(self, days):
        '''
        Get the unx time days ago
        '''
        now = datetime.datetime.now()
        start = (now - datetime.timedelta(days=days)).strftime('%s')
        return start

    def _form_param_for_request_url(self, **kwargs):
        '''
        Forms the pamaters of the request url.
        '''
        request_params = '&'
        for param in kwargs:
            if kwargs[param] and param in self.valid_params:
                try:
                    request_params = '{}{}={}'.format(request_params, param, 
                    ','.join(kwargs[param]))
                except TypeError:
                    if param in self.time_params:
                        tym = self._form_GMT_unix_time(kwargs[param])
                        request_params = '{}{}={}'.format(request_params, param,
                            tym)
                    else:
                        request_params = '{}{}={}'.format(request_params, param, 
                        kwargs[param])
                request_params = '{}&'.format(request_params)
        # Remove the trailing & and return
        request_params = request_params[0:-1]
        return request_params

    def _form_task_request_url(self, **kwargs):
        '''
        Form a url with the task parameters opted in by the user
        '''
       # request_url = ''
        if not self._is_valid_field_list(kwargs['fields']):
            raise SystemExit
        request_url = self._form_param_for_request_url(**kwargs)
        request_url = '{}{}&{}'.format(self.tasks_get_url, self.token, 
            request_url)
        return request_url

    def sync_tasks(self, param_hash, fields=[]):
        '''
        Performs a synchronization with ToodleDo and dumps out tasks to a pickle
        '''
        # Parse and use the fields attribute if it's being used.
        self._get_user_defined_lists(fields)
        request_url = self._form_task_request_url(**param_hash)
        get_tasks = requests.get(request_url)
        self.json_tasks = self._parse_to_json(get_tasks.text)
        pickle.dump(self.json_tasks, open('tasks_queried.pkl', 'wb'))
        # Get user defined lists
        return pickle.load(open('tasks_queried.pkl', 'rb'))

    def _parse_to_json(self, tasks):
        '''
        Takes output of sync_tasks and converts into a json 
        '''
        self.json_tasks = json.loads(tasks)
        return self.json_tasks

    def dump_all_tasks(self):
        '''
        Dumps contents of all tasks  
        '''
        pprint(self.json_tasks)

    def _align_hash_to_task(self, task):#udl, udl_id):
        '''
        Replaces user defined list id to the appropriate hash
        '''
        if len(task) > 2:
            #print task
            for i in task:
                if i in self.user_defined_lists:
                    for n in self.user_defined_lists[i]:
                        if task[i] ==  n['id']:
                            #print i, task[i], n['name']
                            task[i] = n['name']
                        elif task[i] == 0:
                            task[i] = 'Misc/Uncategorized'
        return task

                    #print key, i[key], self.user_defined_lists[key][0]['id']

    def _group_by_goal(self, out={}):
        '''
        Creates a hash for tasks to get displayed by goal. 
        '''
        for i in self.json_tasks:
            for n in i:
                if n == 'goal':
                    goal_name = str(self._align_hash_to_task(i)['goal'])
                    if goal_name not in out:
                        out[goal_name] = {}
                        #print out
                        if str(i['title']) not in out[goal_name]:
                            out[goal_name][str(i['title'])] = str(i['completed'])
    #                        out[goal_name].append([tasks['title'], tasks['completed']])
                    elif goal_name in out and str(i['title']) not in out[goal_name]:
                        out[goal_name][str(i['title'])] = str(i['completed'])
        return out


    def display_tasks_by_goal(self, task):
        '''
        Presents a task in human readable format printed by goal
        '''
        if len(task) < 3:
            print 'Number of Tasks: {}'.format(task['num'])
        else:
            preprocess = self._group_by_goal()
            for i in preprocess:
                if i == 0:
                    print '{}'.format('Misc/No Goals')
                    for n in preprocess[i]:
                        print '{}, Completed {}'.format(n, preprocess[i][n])
                else:
                    print '{} Related Work:'.format(i)
                    for n in preprocess[i]:
                        tym = time.strftime('%Y-%m-%d',time.localtime(int(preprocess[i][n])))
                        print '    {}, Completed {}'.format(n, tym)


'''
{goal} Related Work
'''
'''

({context}) {title}, Completed {completion}

'''




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fields', nargs='*', help='Specify what fields '
                        'you wish to include')
    parser.add_argument('-e', '--end-day', dest='before', type=int,
                        metavar='N DAYS AGO', help='Go back N days and display '
                        'tasks modified *BEFORE* this day')
    parser.add_argument('-s', '--start-day', dest='after', type=int, 
                        metavar='N DAYS AGO', help='Go back N days and display '
                        'tasks modified *AFTER* this day')
    completion = parser.add_mutually_exclusive_group()
    completion.add_argument('-c', '--completed', dest='comp', action='store_const',
                        const='1' , help='Only show completed tasks')
    completion.add_argument('-i', '--incomplete', dest='comp', action='store_const',
                        const='0', help='Only show incomplete tasks')
    parser.add_argument('-t', '--task-id', nargs=1, dest='id', 
                        help='Display a task with specified id number')
    parser.add_argument('-m', '--max', type=int, dest='num', metavar='NUMBER '
                        'OF RECORDS', help='Set a maximum number of records to '
                        'display. Maximum allowed is 1000')
    parser.add_argument('-n', '--new-token', action='store_true',
        help='Authorize a new app and generate a new oauth_token')
    parser.add_argument('-r', '--refresh-token', action='store_true',
        help='Refresh the current auth_token.pkl file')
    args = parser.parse_args()
    if args.num > 1000:
        print 'Maximum number of records toodledo can pull is 1000. {} '\
                'requested\n'.format(args.num)
        raise SystemExit
    if args.new_token:
        toodle = ToodleDoAuthCLI()
        toodle.get_token()
        raise SystemExit
    if args.refresh_token:
        toodle = ToodleDoAuthCLI()
        toodle.refresh()
        raise SystemExit
    toodle = ToodleDoCLI('auth_token.pkl')
    try:
        a = toodle.sync_tasks(vars(args), args.fields)
        #toodle.dump_all_tasks()
        toodle.display_tasks_by_goal(toodle.json_tasks)
    except requests.exceptions.SSLError:
        # An SSL Error will occur if the token needs to refreshed. 
        # Well... refreshing resolves the issue. Not sure what's ACTUALLY bad.
        toodle = ToodleDoAuthCLI()
        toodle.refresh()
    except AttributeError:
        pass
    except requests.exceptions.ConnectionError:
        print 'Cannot connect to api.toodledo.com. Exiting...'
        raise SystemExit
if __name__ == '__main__':
    main()
