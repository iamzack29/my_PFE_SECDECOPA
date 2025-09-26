import hashlib
import random
import time
from flask import Flask, render_template, request, jsonify

# --- FLASK APP INITIALIZATION ---
app = Flask(__name__)

# --- SIMULATION LOGIC (YOUR CODE, ADAPTED FOR FLASK) ---
class SimulationConfig:
    def __init__(self, params):
        self.NUM_NODES = int(params.get('num_nodes', 50))
        self.SIMULATION_ROUNDS = int(params.get('sim_rounds', 500))
        self.ENABLE_SECURITY = bool(params.get('security_enabled', True))
        self.P_CH_PROBABILITY = float(params.get('p_ch_prob', 0.1))
        self.CLUSTER_CAPACITY = int(params.get('cluster_capacity', 5))
        self.TS_THRESHOLD = float(params.get('ts_threshold', 0.5))
        self.E_INITIAL = float(params.get('e_initial', 500))
        self.ATTACK_START_ROUND = int(params.get('attack_start', 50))
        self.ATTACK_END_ROUND = int(params.get('attack_end', 150))
        self.W1, self.W2 = 0.6, 0.4
        self.E_TX, self.E_RX, self.E_COMP, self.E_AGG = 0.8, 0.4, 0.1, 0.2

class StatsCollector:
    def __init__(self):
        self.fnd_round = -1; self.total_energy_consumed = 0; self.falsified_packets_at_bs = 0
        self.total_packets_at_bs = 0; self.detection_round = -1
        self.energy_per_round = []; self.elected_chs_per_round = []; self.refused_joins_per_round = []
        self.exclusions_per_round = []
        self.log_messages = []

    def log(self, message, level="INFO"): self.log_messages.append({'time': time.strftime('%H:%M:%S'), 'msg': message, 'level': level})
    def log_energy(self, amount): self.total_energy_consumed += amount
    def log_fnd(self, round_num):
        if self.fnd_round == -1: self.fnd_round = round_num
    def log_packet_at_bs(self, is_falsified=False):
        self.total_packets_at_bs += 1
        if is_falsified: self.falsified_packets_at_bs += 1
    def log_detection(self, round_num):
        if self.detection_round == -1: self.detection_round = round_num
    def new_round(self):
        self.energy_per_round.append(self.total_energy_consumed); self.elected_chs_per_round.append(0)
        self.refused_joins_per_round.append(0); self.exclusions_per_round.append(0)
    def log_ch_election(self, num): self.elected_chs_per_round[-1] = num
    def log_join_refusal(self): self.refused_joins_per_round[-1] += 1
    def log_exclusion(self): self.exclusions_per_round[-1] += 1

    def get_results_dict(self, config):
        lifetime = self.fnd_round if self.fnd_round != -1 else config.SIMULATION_ROUNDS
        integrity_rate = 100 - (self.falsified_packets_at_bs / (self.total_packets_at_bs or 1)) * 100
        return {
            "mode": "SECDCOPA" if config.ENABLE_SECURITY else "Baseline",
            "table_data": {
                "Network Lifetime": f"{lifetime} rounds",
                "Data Integrity Rate": f"{integrity_rate:.2f}%" if config.ENABLE_SECURITY else "N/A",
                "Malicious Detection Time": f"{self.detection_round - config.ATTACK_START_ROUND} rounds" if self.detection_round != -1 else "N/A",
                "Falsified Packets at BS": self.falsified_packets_at_bs,
                "Total Energy Consumed": f"{self.total_energy_consumed:.2f} mJ",
                "Avg. Energy/Node/Round": f"{(self.total_energy_consumed / (config.NUM_NODES * lifetime)):.3f} mJ"
            },
            "plot_data": {
                "energy": self.energy_per_round, "chs": self.elected_chs_per_round,
                "refusals": self.refused_joins_per_round, "exclusions": self.exclusions_per_round,
                "total_packets": self.total_packets_at_bs, "falsified_packets": self.falsified_packets_at_bs
            },
            "log": self.log_messages
        }

def hash_message(m): return hashlib.sha256(str(m).encode()).hexdigest()
def speck_encrypt(p, k): return p[::-1] + k[:4]
def speck_decrypt(c, k): return c[:-4][::-1]
def sign_message(m, sk): return hash_message(m + str(sk))
def verify_signature(m, sig, pk, keys):
    for _, k in keys.items():
        if k['pk'] == pk: return sig == hash_message(m + str(k['sk']))
    return False

class SensorNode:
    def __init__(self, id, cfg, stats):
        self.id, self.config, self.stats = id, cfg, stats
        self.private_key, self.public_key = random.randint(1000, 99999), random.randint(100000, 999999)
        self.energy = self.config.E_INITIAL
        self.is_ch, self.cluster_head, self.cluster_key = False, None, None
        self.round_last_ch = -1 / (self.config.P_CH_PROBABILITY + 1e-9)
        self.seq, self.valid_msg, self.total_msg, self.is_dead = 0, 0, 0, False
    def elect_as_ch(self, r):
        self.is_ch = False
        if self.is_dead or r - self.round_last_ch < (1 / self.config.P_CH_PROBABILITY): return None
        if random.random() < self.config.P_CH_PROBABILITY:
            self.is_ch = True; self.round_last_ch = r; return ClusterHead(self, self.config, self.stats)
        return None
    def join(self, chs):
        if not self.is_ch and chs and not self.is_dead: random.choice(chs).initiate_join(self, chs)
    def receive_accept(self, k, ch): self.cluster_key, self.cluster_head = k, ch
    def update_key(self, nk): self.cluster_key = nk
    def revoke(self): self.cluster_key, self.cluster_head = None, None
    def send_data(self, r):
        if not self.cluster_key or self.is_dead: return None
        self.seq += 1; self.total_msg += 1
        cost = self.config.E_COMP + self.config.E_TX
        self.energy -= cost; self.stats.log_energy(cost)
        if self.energy <= 0: self.is_dead = True; self.stats.log_fnd(r); return None
        plain = f"data_{self.id}_{self.seq}"; return {'sender': self, 'cipher': speck_encrypt(plain, self.cluster_key), 'hash': hash_message(plain), 'seq': self.seq}

class ClusterHead:
    def __init__(self, node, cfg, stats):
        self.id, self.config, self.stats = node.id, cfg, stats
        self.pk, self.sk = node.public_key, node.private_key; self.key = str(random.randint(1000, 9999))
        self.members, self.trust, self.seq_hist, self.excluded = [], {}, {}, []
    def initiate_join(self, node, all_chs):
        if not self.config.ENABLE_SECURITY: self.accept(node); return
        if len(self.members) >= self.config.CLUSTER_CAPACITY: self.stats.log_join_refusal(); return
        if [ch.vote() for ch in all_chs].count("APPROVE") > len(all_chs)//2: self.accept(node)
        else: self.stats.log_join_refusal()
    def vote(self): return "APPROVE" if len(self.members) < self.config.CLUSTER_CAPACITY else "REJECT"
    def accept(self, node): self.members.append(node); self.trust[node.id] = 1.0; node.receive_accept(self.key, self)
    def receive_data(self, msg, r):
        node = msg['sender']; self.stats.log_energy(self.config.E_RX)
        if self.config.ENABLE_SECURITY and (node.id in self.excluded or self.seq_hist.get(node.id, 0) >= msg['seq']): return
        self.seq_hist[node.id] = msg['seq']
        if hash_message(speck_decrypt(msg['cipher'], self.key)) == msg['hash']: node.valid_msg += 1
        if self.config.ENABLE_SECURITY: self.update_trust(node, r)
    def update_trust(self, node, r):
        self.stats.log_energy(self.config.E_COMP)
        ts = self.config.W1 * (node.valid_msg / (node.total_msg or 1)); self.trust[node.id] = ts
        if ts < self.config.TS_THRESHOLD and node.id not in self.excluded:
            self.stats.log_detection(r); self.excluded.append(node.id); self.stats.log_exclusion()
            self.members = [m for m in self.members if m.id != node.id]; node.revoke(); self.rotate_key()
    def rotate_key(self):
        if not self.config.ENABLE_SECURITY: return
        self.key = str(random.randint(1000, 9999))
        for member in self.members: member.update_key(self.key)
    def send_to_bs(self, bs, mal):
        if not self.members and not self.excluded: return
        self.stats.log_energy(self.config.E_AGG + self.config.E_TX); r = f"CH_{self.id}"
        bs.receive_data(r, sign_message(r, self.sk), self.pk, mal)

class BaseStation:
    def __init__(self, id, keys, stats): self.id, self.keys, self.stats = id, keys, stats
    def receive_data(self, r, sig, pk, mal):
        if verify_signature(r, sig, pk, self.keys): self.stats.log_packet_at_bs(is_falsified=mal)

def do_simulation(params):
    config = SimulationConfig(params)
    stats = StatsCollector()
    stats.log(f"Starting: {config.NUM_NODES} nodes, {config.SIMULATION_ROUNDS} rounds for {'SECDCOPA' if config.ENABLE_SECURITY else 'Baseline'}", "INFO")
    nodes = [SensorNode(i, config, stats) for i in range(1, config.NUM_NODES + 1)]
    keys = {n.id: {'pk': n.public_key, 'sk': n.private_key} for n in nodes}
    bs = BaseStation(0, keys, stats)
    mal_node = random.choice(nodes)
    stats.log(f"Malicious node selected: SN_{mal_node.id}", "WARN")

    for r in range(1, config.SIMULATION_ROUNDS + 1):
        if stats.fnd_round != -1: stats.log(f"First node died. Stopping at round {r}.", "WARN"); break
        stats.new_round()
        active_chs = [ch for ch in [n.elect_as_ch(r) for n in nodes if not n.is_dead] if ch is not None]
        stats.log_ch_election(len(active_chs))
        if r % 100 == 0: stats.log(f"Round {r}/{config.SIMULATION_ROUNDS} | Active CHs: {len(active_chs)}", "EVENT")
        if not active_chs: continue
        for node in nodes: node.join(active_chs)
        for node in nodes:
            if not node.is_ch and node.cluster_head:
                msg = node.send_data(r)
                if msg:
                    if node.id == mal_node.id and config.ATTACK_START_ROUND <= r < config.ATTACK_END_ROUND: msg['hash'] = "wrong"
                    for ch in active_chs:
                        if ch.id == node.cluster_head.id: ch.receive_data(msg, r); break
        for ch in active_chs:
            compromised = ch.id == mal_node.id or any(m.id == mal_node.id for m in ch.members)
            attack = config.ATTACK_START_ROUND <= r < config.ATTACK_END_ROUND
            ch.send_to_bs(bs, compromised and attack)
            if r % 20 == 0: ch.rotate_key()
    stats.log("Simulation finished.", "INFO")
    return stats.get_results_dict(config)

# --- FLASK ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run():
    params = request.get_json()
    run_type = params.get("run_type")
    
    if run_type == "compare":
        params['security_enabled'] = False
        baseline_results = do_simulation(params)
        
        params['security_enabled'] = True
        secdcopa_results = do_simulation(params)
        
        return jsonify({"baseline": baseline_results, "secdcopa": secdcopa_results})
    else: # single run
        is_secure = run_type == "secdcopa"
        params['security_enabled'] = is_secure
        results = do_simulation(params)
        key = "secdcopa" if is_secure else "baseline"
        return jsonify({key: results})

if __name__ == '__main__':
    app.run(debug=True)