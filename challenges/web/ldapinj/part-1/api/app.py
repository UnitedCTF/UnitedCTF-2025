from flask import Flask, jsonify, request
from ldap3 import Server, Connection, SUBTREE, ALL
from ldap3.core.exceptions import LDAPException

app = Flask(__name__)

@app.route('/search')
def list_users():
    lo = request.args.get('lo')
    ro = request.args.get('ro')
    if not lo or not ro:
        return jsonify({'error': 'Missing parameter'}), 400

    try:
        server = Server('ldap://ldap', get_info=ALL)
        conn = Connection(server, user='cn=admin,dc=cloridorme,dc=unitedctf', password='royaumedefinlande', auto_bind=True)

        search_base = "ou=users,dc=cloridorme,dc=unitedctf"
        search_filter = f"(&({lo})({ro}))"
        
        conn.search(search_base, search_filter, search_scope=SUBTREE, attributes='*')

        users = []
        for entry in conn.entries:
            user = {
                'dn': str(entry.entry_dn),
                'attributes': {attr: entry[attr].value if not isinstance(entry[attr].value, list) else entry[attr].value for attr in entry.entry_attributes}
            }
            users.append(user)

        return jsonify(users)
    except Exception as e:
        return jsonify({'query': f"(&({lo})({ro}))" ,'error': str(e)}), 200