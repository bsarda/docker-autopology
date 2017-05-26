import sys
USER_LOCAL_PYTHONPATH = '/usr/local/lib/python2.7/dist-packages/'
USR_LIB_PYTHONPATH = '/usr/lib/python2.7/dist-packages/'
if USER_LOCAL_PYTHONPATH not in sys.path:
    sys.path.append(USER_LOCAL_PYTHONPATH)
if USR_LIB_PYTHONPATH not in sys.path:
    sys.path.append(USR_LIB_PYTHONPATH)

from flask import Flask, jsonify, request, session, redirect, url_for, send_from_directory, render_template  # noqa
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from OpenSSL import crypto
from simplepam import authenticate
from threading import Timer
import argparse
import getpass
import logging
import os
import requests
import socket
import ssl
import yaml
import uuid

import config
import core

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_SECURE'] = True
csrf = CSRFProtect(app)

log = logging.getLogger('autopology')


SESSION_KEY = str(uuid.uuid4().int)
SESSION_TIMEOUT = 300
current_sessions = {}


@app.errorhandler(Exception)
def handle_server_exception(error):
    """
    Called in case of any Exception in API methods.
    This returns a meaningful json with exception message and status code
    defaulting to 500 (Internal Server Error).

    Without this, an exception would cause ugly 'Internal Server Error' like:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
    <title>500 Internal Server Error</title>
    <h1>Internal Server Error</h1>
    <p>The server encountered an internal error and was unable to complete your
       request.  Either the server is overloaded or there is an error in the
       application.</p>


    This method results in a pretty exception like:
    {
      "message": "Some Exception in get_inventory()"
    }
    """
    # Build a json and assign status code.
    response = dict()
    response['message'] = str(error)
    response = jsonify(response)
    response.status_code = 500
    # Log the exception in server logs before returning json.
    log.exception(error)
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    response = dict()
    response['message'] = str(e.description)
    response = jsonify(response)
    response.status_code = 400
    log.exception(e.description)
    return response


def requires_auth(f):
    """
    Verifies if session if already authenticated via the login page.
    A session is expected to be of form {session_key: session_value}.

    This method verifies if session key and session value are recognised by
    this server, else redirects to login page.

    If the session is recognised, it checks if the session is expired/stale.
    If stale, redirects to login page, else refreshes the timer and redirects
    to desired page.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if SESSION_KEY in session and session[SESSION_KEY] in current_sessions:
            session_uuid = session[SESSION_KEY]
            if not _reset_session_timer(session_uuid):
                # Session already expired. , redirect to login page.
                return redirect(url_for('login_form'))
            # Session active, redirect to desired page.
            return f(*args, **kwargs)
        else:
            # Session not authenticated, redirect to login page.
            return redirect(url_for('login_form'))
    return decorated


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Frame-Options'] = 'deny'
    response.headers['X-XSS-Protection'] = 1
    return response

@app.route('/<path:path>')
@requires_auth
def index(path):
    return send_from_directory('ui/', path)


@app.route('/')
@requires_auth
def index1():
    return send_from_directory('ui/', 'index.html')


@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    username = request.form['username']
    password = request.form['password']
    if authenticate(str(username), str(password)):
        # Username/Password are authenicated via linux simplepam module.
        if SESSION_KEY in session and session[SESSION_KEY] in current_sessions:
            # Session already existing/recognised on this server
            return redirect(url_for('index', path='index.html'))

        # New session, track by associating a unique UUID with this session and
        # maintaining a dict of recognised active sessions.
        # The value in the dict is timer object that is designed to self-delete
        # the session entry from current_session list when timer goes off.
        session_uuid = uuid.uuid4().int
        session[SESSION_KEY] = session_uuid
        _reset_session_timer(session_uuid, new_session=True)
        return redirect(url_for('index', path='index.html'))
    else:
        return render_template('login.html', cls='error active')


@app.route('/login', methods=['GET'])
def login_form():
    return render_template('login.html', cls='error')


@app.route('/logout')
@requires_auth
def logout():
    """
    Removes session from current_sessions list.
    Also removes the SESSION_KEY associated with that session.
    """
    current_sessions.pop(session[SESSION_KEY])
    session.pop(SESSION_KEY, None)
    return redirect(url_for('login_form'))


def delete_stale_session(session_uuid):
    """
    Deletes the session_uuid entry from current_sessions dict.
    """
    current_sessions.pop(session_uuid)


def _reset_session_timer(session_uuid, new_session=False):
    if not new_session:
        try:
            # First try to cancel existing timer for this session.
            current_sessions[session_uuid].cancel()
        except KeyError:
            # If session_uuid isn't found in current_sessions dict, it
            # means session has already expired.
            return False
    t = Timer(SESSION_TIMEOUT, delete_stale_session, [session_uuid])
    current_sessions[session_uuid] = t
    current_sessions[session_uuid].start()
    return True


@app.route('/api/v2/csrf_token/', methods=['GET'])
@requires_auth
def get_csrf_token():
    foo = URLSafeTimedSerializer(app.secret_key, salt='wtf-csrf-token')
    return foo.dumps(session['csrf_token'])


@app.route('/api/v2/manager-ip/', methods=['GET'])
@requires_auth
def get_manager_ip():
    return core.topo.nsxmanagers[0].ip


@app.route('/api/v2/topologies/', methods=['GET'])
@app.route('/api/v2/topologies/<uid>', methods=['GET'])
@requires_auth
def get_topologies_api(uid=None):
    if uid:
        if uid == '_system':
            core.topo.fetch()
            return jsonify(core.topo.build(inventory=core.topo.inventory))
        # Below call will populate the url and ID from Rishabh's code.
        res = core.bulk_to_compact(core._get_bulk_api(uid),
                                   core.topo.topodict.get(uid))
        res.update(core._get_bulk_state(uid))
    else:
        res = core.topo.topodict.get()
    core.topo.dump()
    return jsonify(res)


@app.route('/api/v2/monitor/', methods=['POST'])
@requires_auth
def create_topology_monitor():
    data = request.json
    res = core._post_monitor_api(data)
    return jsonify(res)


@app.route('/api/v2/monitor/<uid>/autobot', methods=['POST'])
@requires_auth
def create_monitor_autobot(uid):
    data = request.json
    core.topo.monitordict.set(uid, 'autobot', data['enabled'])
    core.topo.monitordict.append(uid, 'events', dict(name='autobot',
                                                     message='Hello World! :)',
                                                     type='SUCCESS'))
    return jsonify(core.topo.monitordict.get(uid))


@app.route('/api/v2/monitor/<uid>', methods=['GET'])
@requires_auth
def get_monitor_response(uid):
    return jsonify(core.topo.monitordict.get(uid))


@app.route('/api/v2/monitor/<uid>/events', methods=['GET'])
@requires_auth
def get_monitor_events(uid):
    return jsonify(core.topo.get_monitor_events(uid))
    return jsonify(yaml.load(open('sample/get_events_response.yaml')))


@app.route('/api/v2/topologies/<uid>/state', methods=['GET'])
@app.route('/api/v2/bulk/<uid>/state', methods=['GET'])
@requires_auth
def get_bulk_state(uid=None):
    return jsonify(core._get_bulk_state(uid))


@app.route('/api/v2/bulk/', methods=['POST'])
@requires_auth
def post_bulk_api():
    data = request.json
    res = core._post_bulk_api(data)
    return jsonify(res)


@app.route('/api/v2/bulk/', methods=['GET'])
@app.route('/api/v2/bulk/<uid>', methods=['GET'])
@requires_auth
def get_bulk_api(uid=None):
    res = core._get_bulk_api(uid)
    return jsonify(res)


@app.route('/api/v2/topologies/', methods=['POST'])
@requires_auth
def post_topologies_api():
    data = request.json
    res = core._post_topologies_api(data)
    return jsonify(res)


@app.route('/api/v2/topologies/<uid>', methods=['DEL'])
@app.route('/api/v2/bulk/<uid>', methods=['DEL'])
@requires_auth
def del_bulk_api(uid=None):
    res = core._del_bulk_api(uid)
    return jsonify(res)


@app.route('/api/v2/inventory/', methods=['GET'])
@requires_auth
def get_inventory_api():
    ret = core._get_inventory_api()
    return jsonify(ret)


def fetch_existing_topologies():
    """
    Fetches any existing topologies on manager and saves it to topodict.
    """
    core.topo.fetch()
    existing_topo = core.topo.build(inventory=core.topo.inventory)
    if existing_topo:
        existing_specs = core._preprocess_existing_topo(existing_topo)
        for spec in existing_specs:
            core._preprocess_topology_spec(None, spec)


def get_mgmt_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("vmware.com", 80))
    mgmt_ip = s.getsockname()[0]
    s.close()
    log.info("Autodetected autopology server ip: %s" % mgmt_ip)
    return mgmt_ip


def generate_keys():
    home = os.path.expanduser("~")
    autopology_key = "%s/.autopology.key" % home
    autopology_cert = "%s/.autopology.cert" % home
    if not os.path.isfile(autopology_key):
        print("Generating %s" % autopology_key)
        os.system('openssl genrsa -out %s 2048' % autopology_key)
    if not os.path.isfile(autopology_cert):
        print("Generating %s" % autopology_cert)
        os.system('openssl req -new -x509 -sha256 -key %s -out %s -days 365 -subj /CN=autopology.vmware.com' % (autopology_key, autopology_cert))  # noqa
    return (autopology_key, autopology_cert)


def wellknown_cert(manager_ip, manager_username, manager_password):
    manager_url = 'https://%s' % manager_ip
    auth = (manager_username, manager_password)
    try:
        r = requests.get(manager_url, auth=auth)
    except requests.exceptions.SSLError as e:
        if 'certificate verify failed' in str(e.message):
            return False
    return True


def get_cert(manager_ip):
    cert_pem = ssl.get_server_certificate((manager_ip, 443))
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    cn = cert.get_subject().CN
    return cert_pem, cn


def create_cert_file(cert, cert_file=None):
    home = os.path.expanduser("~")
    if not cert_file:
        cert_file = '%s/.nsx_cert.pem' % home
    else:
        cert_file = '%s/%s' % (home, cert_file)
    f  = open(cert_file, 'w')
    f.write(cert)
    f.close()
    return cert_file


def main():
    ''' Main method '''
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-n', '--num-threads',
        default=core.DEFAULT_NUM_THREADS,
        type=int, help='Number of threads to make api calls')
    args = parser.parse_args(sys.argv[1:])
    config.configure_logging(app=app)

    (autopology_key, autopology_cert) = generate_keys()

#    manager_ip = raw_input('Enter NSX Manager Hostname: ')
#    manager_username = raw_input('Enter NSX Manager username: ')
#    manager_password = getpass.getpass('Enter NSX Manager password: ')
    manager_ip = os.environ['MANAGER_IP']
    manager_username = os.environ['MANAGER_USERNAME']
    manager_password = os.environ['MANAGER_PASSWORD']
    known_cert = wellknown_cert(manager_ip, manager_username, manager_password)
    if known_cert:
        nsx_cert_file = None
    else:
        cert, cn = get_cert(manager_ip)
#        allow_self_signed = raw_input('Untrusted security certificate found.'
#                                      '\n%s\nTrust this certificate ? [Y/N]: '
#                                      % cert)
#        if (allow_self_signed.lower() == 'y' or
#            allow_self_signed.lower() == 'yes'):
#        cert_file = raw_input('Enter filename to store the certificate.'
#                              '[Blank for default (~/.nsx_cert.pem)]: ')
        cert_file=""
        nsx_cert_file = create_cert_file(cert, cert_file=cert_file)
        log.info("Plase use %s as the hostname for NSX manager: " % cn)
#        else:
#            log.info("Please use a well known certificate for NSX Manager "
#                     "and try again or allow untrusted ceritificates.")
#            sys.exit(0)
#    esx_password = getpass.getpass('Enter ESX root password: ')
    esx_password = os.environ['ESX_PASSWORD']
#    kvm_password = getpass.getpass('Enter KVM root password: ')
    kvm_password = os.environ['KVM_PASSWORD']
#    port = raw_input('Enter port number for server to listen: ')
    port = 443
    if config.ALLOW_VM_SSH:
        vm_password = getpass.getpass('Enter guest VM root password: ')
    else:
        vm_password = "Unused"  # dummy, not used

    testbed = {
        "esx": {
            "default": {
                "password": esx_password,
                "username": 'root'
            }
        },
        "kvm": {
            "default": {
                "password": kvm_password,
                "username": 'root'
            }
        },
        "nsxmanager": {
            manager_ip: {
                "ip": manager_ip,
                "password": manager_password,
                "username": manager_username,
                "nsx_cert_file": nsx_cert_file,
            }
        },
        "vm": {
            "default": {
                "password": vm_password,
                "username": 'root'
            }
        }
    }

    if os.fork():
        sys.exit(0)  # Parent process will exit here.

    # Child process will keep running in background.
    try:
        core.configure_testbed(testbed, args.num_threads)
        # XXX: Not needed for Autopology.
        # fetch_existing_topologies()
        print("Successfully started Autopology Server\n")
        print("Use the URL - https://<your machine ip>:%s to access "
              "Autopology Web Interface." % port)
        log.info("Starting autopology server at 0.0.0.0:%s" % port)
        app.run(host='0.0.0.0', port=port,
                ssl_context=(autopology_cert, autopology_key))
    except:
        print("Failed to start Autopology Server\n")
        print("Please refer to /tmp/autopology.log for more information.")
        log.exception("Error starting Autopology Server")
        raise

if __name__ == "__main__":
    main()
