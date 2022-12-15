# Functions for managing multi-tenant Wireguard server
import wgconfig, os, logging, base64, ipaddress, json, np_db, os, subprocess, requests
from datetime import datetime, timedelta
from subprocess import Popen, PIPE

logging.root.setLevel(logging.INFO)
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))


# Important note:
# Pubkey provided by controller is b64-encoded;
# We decode it before we hand it off to wgconfig and
# re-encode when we query the db so we can keep it URL-safe

interface = 'wg0'
wgconf = '/etc/wireguard/wg0.conf'
root_domain = os.getenv('ROOT_DOMAIN')
wc = wgconfig.WGConfig('/etc/wireguard/wg0.conf')
subnet = ipaddress.ip_network('10.13.13.0/24')
hosturl = f'anchor.{root_domain}'

# Generate the public key for the server's private key
def wg_pubkey():
    wc.read_file()
    privkey = wc.interface['PrivateKey']
    raw_pub = Popen(f'echo {privkey}|wg pubkey', stdout=PIPE, stderr=None, shell=True).communicate()[0]
    srv_pub = raw_pub.strip().decode('utf-8')
    return srv_pub

srv_pubkey = wg_pubkey()

# Reset interface
# Restart with preup list, insert predown rules, restart again, remove predown
def restart_wg():
    logging.info('[WG]: Restarting interface...')
    hook_auth = os.getenv('HOOK_AUTH')
    url = f"http://172.20.0.2:9000/hooks/restart-wg?token={hook_auth}"
    try:
        resp = requests.get(url)
        msg = resp.content.decode('utf-8')
    except Exception as e:
        logging.error(f'[WG]: Failed to parse response from webhook {e}')
        return False
    if resp.status_code == 200:
        logging.info('[WG]: WG interface restarted')
        # remove_predowns()
        # fwd_predown_rules()
        os.system(f'cp {wgconf} {wgconf}.bak')
        return True
    else:
        title = f'{hosturl} Could not restart IF'
        logging.error(f'[WG]: Could not restart WG: {msg}')
        sg_api.send_email(title,msg)
        return False

# Does this pubkey exist?
def check_peer(pubkey):
    wc.read_file()
    pubkey = pubkey_decode(pubkey)
    peer_list = list(dict.keys(wc.peers))
    if pubkey in peer_list:
        # Return its IP if so
        peer_ip = wc.peers[pubkey]['AllowedIPs']
        peer_ip = str(ipaddress.ip_network(peer_ip)[0])
        return peer_ip
    else:
        return False

# Generate and return client configuration
def get_conf(pubkey):
    wc.read_file()
    pubkey = pubkey_decode(pubkey)
    peer_ip = wc.peers[pubkey]['AllowedIPs']
    port = wc.interface['ListenPort']
    template = f'''[Interface]
PrivateKey = privkey
Address = {peer_ip}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {srv_pubkey}
AllowedIPs = 0.0.0.0/0
Endpoint = {hosturl}:{port}
PersistentKeepalive = 20'''
    temputf = template.encode('utf-8')
    confb64 = base64.b64encode(temputf).decode('utf-8')
    return confb64

# Create a new peer with a label
def new_peer(label,pubkey):
    wc.read_file()
    avail_ip = next_ip(pubkey)
    logging.info(f'[WG]: Provisioning {avail_ip} for {pubkey}')
    if check_peer(pubkey) == False:
        try:
            dec_pubkey = pubkey_decode(pubkey)
            wc.add_peer(dec_pubkey)
            wc.add_attr(f'{dec_pubkey}','AllowedIPs',f'{avail_ip}')
            wc.write_file()
            restart_wg()
            conf = get_conf(pubkey)
            np_db.upd_value('anchors','conf',conf,'pubkey',pubkey)
            return True
        except Exception as e:
            logging.exception(f'[WG]: Provisioning error: {e}')
            return False
    else:
        return True

# Return a list of all peers (b64'd)
def peer_list():
    wc.read_file()
    peerlist = list(wc.peers)
    returnlist = []
    for peer in peerlist:
        # We have to add a \n so that it will match that generated
        # by `wg genkey|wg pubkey|base64 -w 0`
        peer = f'{peer}\n'
        peer = peer.encode('utf-8')
        peer = base64.b64encode(peer).decode('utf-8')
        returnlist.append(peer)
    return returnlist

# Get DB-encoded pubkey for an IP
def get_ip_pubkey(ip):
    ip_net = f'{ip}/32'
    wc.read_file()
    data = wc.peers
    enc_peers = list(data)
    dec_peers = peer_list()
    dec_ip, enc_ip, result = {}, {}, ''
    for peer in data:
        peer_ip = data[peer]['AllowedIPs']
        if peer_ip == ip_net:
            result = pubkey_encode(peer)
    if result != '':
        return result
    else:
        return None

# Delete a peer or list of peers
def del_peer(pubkey):
    if isinstance(pubkey,list):
        count = 0
        for peer in pubkey:
            if check_peer(peer) != False:
                try:
                    pub = pubkey_decode(peer)
                    wc.del_peer(pub)
                    wc.write_file()
                    count += 1
                    logging.info(f'[WG]: Peer {peer} deleted')
                except Exception as e:
                    logging.exception(f'[WG]: Peer {peer} not deleted:',e)
        restart_wg()
    elif isinstance(pubkey,str):
        if check_peer(pubkey) != False:
            try:
                pubkey = pubkey_decode(pubkey)
                wc.del_peer(pubkey)
                wc.write_file()
                logging.info(f'[WG]: Peer {pubkey} deleted')
                restart_wg()
                return
            except Exception as e:
                logging.exception(f'[WG]: Peer {pubkey} not deleted:',e)
                return e
    else:
        logging.warning(f'[WG] Invalid pubkey for deletion: {pubkey}')

# Convert b64 pubkey to wg format
def pubkey_decode(pubkey):
    pubkey = base64.b64decode(pubkey)
    return pubkey.strip().decode('utf-8')

# Returns a /32 IPv4Network type
def next_ip(pubkey):
    wc.read_file()
    pubkey = pubkey_decode(pubkey)
    peer_list = list(dict.keys(wc.peers))
    # If we already have this pubkey, return the IP
    if pubkey in peer_list:
        return ipaddress.ip_network(wc.peers[pubkey]['AllowedIPs'])
    else:
        ip_list, net_list = [], []
        for index in range(0,3):
            ip_list.append(subnet[index])
        for peer in peer_list:
            # Construct a list of used & reserved addresses
            net_list.append(ipaddress.ip_network(wc.peers[peer]['AllowedIPs']))
            for net in net_list:
                ip_list.append(net[0])
        # Dedupe and get the next available
        ip_list = list(dict.fromkeys(ip_list))
        hosts_iterator = (host for host in subnet.hosts() if host not in ip_list)
        avail_ip = next(hosts_iterator)
        return ipaddress.ip_network(f'{avail_ip}/32')


# Create iptables rule for direct port forwarding (Ames)
def port_fwd(peer,port,protocol):
    # Generate rules from templates
    def rule_gen(rule,ad):
        if ad == 'A':
            prefix = 'PreUp'
        elif ad == 'D':
            prefix = 'PreDown'
        else:
            return False
        fwd_rule = f'{prefix} = iptables -{ad} FORWARD -p \
{protocol} -d {peer} --dport {port} -j ACCEPT\n'
        preroute_rule = f'{prefix} = iptables -{ad} PREROUTING \
-t nat -p {protocol} -i eth0 --dport {port} -j DNAT --to-destination \
{peer}:{port}\n -m comment --comment "fwded"\n'
        if rule == 'fwd':
            return fwd_rule
        elif rule == 'pre':
            return preroute_rule
        else:
            return False
    # No duplicates
    exists = fwd_exists()
    port = int(port)
    if (protocol in exists.keys()) and (port not in exists[protocol].keys()):
        logging.info(f'[WG]: Adding direct port forwarding for \
{peer}:{port}/{protocol}')
        with open("/etc/wireguard/wg0.conf", "r") as f:
            contents = f.readlines()
            for num, line in enumerate(contents, 1):
                # Find the line number to insert PreUp rules
                if 'PostUp' in line:
                    index = num -1
        pre = rule_gen('pre','A')
        fwd = rule_gen('fwd','A')
        contents.insert(index, pre)
        contents.insert(index, fwd)
        if (pre != False) and (fwd != False):
            with open("/etc/wireguard/wg0.conf", "w") as f:
                contents = "".join(contents)
                f.write(contents)
                return True
        else:
            logging.warning(f'[WG]: Invalid routing rule')
            return False
    # You still need to restart the interface

# Remove a forwarding rule from WG conf
def remove_fwd(port):
    port = str(port)
    lookup = f'--dport {port}'
    # Remove the PreUp rule
    linematch,preups,predowns = [],[],[]
    with open(wgconf, "r") as f:
        lines = f.readlines()
    for line in lines:
        if lookup in line:
            linematch.append(lines.index(line))
    preups = linematch[0:2]
    predowns = linematch[2:4]
    with open(wgconf, 'w') as f:
        for number, line in enumerate(lines):
            if number not in preups:
                f.write(line)
    # Restart after the PreUp rule is removed
    # in order to be able to remove PreDown
    restart_wg()
    # Remove the PreDown rule (no restart)
    with open(wgconf, "r") as f:
        lines = f.readlines()
    with open(wgconf, 'w') as f:
        for number, line in enumerate(lines):
            if number not in predowns:
                f.write(line)

# Return a dict of all existing port forwards
# {tcp:{port:peer,port:peer},udp:{port:peer}}
def fwd_exists():
    results = {'tcp':{},'udp':{}}
    with open("/etc/wireguard/wg0.conf","r+") as f:
        lines = f.readlines()
        f.seek(0)
        for line in lines:
            if ('PreUp' in line) and ('FORWARD' in line):
                match = '--dport'
                before, _, after = line.partition(match)
                protocol = before.split()[-3]
                peer = before.split()[-1]
                port = int(after.split()[0])
                fwd = {port:peer}
                results[protocol][port]=peer
    return results

# Compare dict of forwarded services vs existing forwards
def rectify_port_fwd(fwd_input):
    # restart_wg()
    # {udp:{port:peer,port:peer},tcp:{port:peer}}
    def port_list(port_input):
        # Create lists of ports from fwd_input/fwd_exist
        # We don't allow overlaps for tcp/udp numbers
        result = []
        if 'tcp' in port_input.keys():
            result += list(port_input['tcp'].keys())
        if 'udp' in port_input.keys():
            result += list(port_input['udp'].keys())
        return result
    # Get existing fwds and make lists
    fwd_exist = fwd_exists()
    exist_list = port_list(fwd_exist)
    input_list = port_list(fwd_input)
    # Return value will let us know if anything changed,
    # and which peers need to have DB status updated
    result = {'mod':0,'peers':[]}
    try:
        for protocol in fwd_input:
            for port in fwd_input[protocol]:
                # Add missing forwards
                if (port in fwd_input[protocol].keys()) and \
                (port not in fwd_exist[protocol].keys()):
                    logging.info(f'[WG] Rectify: Adding forwarding for {port}')
                    input_peer = fwd_input[protocol][port]
                    port_fwd(input_peer,port,protocol)
                    fwd_exist = fwd_exists()
                    result['mod'] = 1
                    result['peers'].append(get_ip_pubkey(fwd_input))
                # Fix erroneous existing forwards
                if (port in exist_list) and \
                (fwd_input[protocol][port] != fwd_exist[protocol][port]):
                    logging.info(f'[WG] Rectify: Removing forwarding for {port}')
                    input_peer = fwd_input[protocol][port]
                    remove_fwd(port)
                    port_fwd(input_peer,port,protocol)
                    fwd_exist = fwd_exists()
                    result['mod'] = 1
                    result['peers'].append(get_ip_pubkey(fwd_input))
        # Delete old forwards
        for port in exist_list:
            if not (port in input_list):
                logging.info(f'[WG] Rectify: Removing forwarding for {port}')
                remove_fwd(port)
                result['mod'] = 1
        return result
    except Exception as e:
        msg = e
        logging.error(f'[WG]: Could not restart WG: {e}')
        sg_api.send_email(f'WG:{hostname}',msg)
        return False

# Create PreDown rules after interface restart
# We can't restart it if it has an invalid rule
def fwd_predown_rules():
    pres = []
    with open(wgconf, "r") as f:
        contents = f.readlines()
        for num, line in enumerate(contents, 1):
            if ("--dport" in line) and ("PreUp" in line):
                substr = "PreUp = iptables -A"
                replace = "PreDown = iptables -D"
                # Create matching PreDown rules
                post_rule = line.replace(substr,replace)
                # Ignore this in stdout in case it's an unapplied rule
                if '&' not in post_rule:
                    post_rule = post_rule.replace('\n',' &\n')
                pres.append(post_rule)
    with open(wgconf, "r") as f:
        contents = f.readlines()
        for num, line in enumerate(contents, 1):
            # Find the line numbers to insert PreDown rules
            if 'PostDown' in line:
                index = num - 1
        for rule in pres:
            # Append deletion rules if they don't exist
            if rule not in contents:
                contents.insert(index,rule)
        contents = "".join(contents)
    with open(wgconf, "w+") as f:
        f.write(str(contents))
        logging.info(f'fwd_predown_rules(): {contents}')
    pred = len(pres)
    logging.info(f'[WG]: Inserted {pred} PreDown rules')

# Remove all predown rules (for restart_wg)
def remove_predowns():
    with open(wgconf, "r") as f:
        lines = f.readlines()
    count,keep = 0,[]
    for num,line in enumerate(lines):
        if 'PreDown' not in line:
            keep.append(num)
        count += 1
    with open(wgconf, 'w') as f:
        for num,line in enumerate(lines):
            if num in keep:
                f.write(line)
    return True