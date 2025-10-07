from flask import Flask, jsonify, request
from ldap3 import Server, Connection, SUBTREE, ALL

app = Flask(__name__)

forbidden_chars = {"*", "(", ")", "/", "\\"}

@app.route('/search')
def list_users():
    ou = request.args.get('ou')
    sn = request.args.get('sn')

    if not ou or not sn:
        return jsonify({'error': 'Missing parameter'}), 400
    if forbidden_chars.intersection(ou.strip()):
        return jsonify({'error': 'Invalid OU'}), 400
    if forbidden_chars.intersection(sn.strip()):
        return jsonify({'error': 'Invalid SN'}), 400
    
    try:
        server = Server('ldap://ldap', get_info=ALL)

        # Connection information for the bind, not an actual LDAP entry.
        conn = Connection(server, user='cn=admin,dc=cloridorme,dc=unitedctf', password='aimes-tu-les-animaux', auto_bind=True)

        search_base = "dc=cloridorme,dc=unitedctf"

        if ou.strip() != "":
            search_base = f"ou={ou}," + search_base
        
        search_filter = f"({sn})"
        
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
        return jsonify({'error': str(e)}), 500