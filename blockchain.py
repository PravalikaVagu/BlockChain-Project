import hashlib
import json
from time import time
from urllib.parse import urlparse
import requests # Added for node consensus

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(proof=100, previous_hash='1')

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid
        :param chain: a blockchain
        :return: True if valid, False if not
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # print(f'{last_block}')
            # print(f'{block}')
            # print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our Consensus Algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain', timeout=5) # Added timeout
                if response.status_code == 200:
                    data = response.json()
                    length = data['length']
                    chain = data['chain']

                    # Check if the length is longer and the chain is valid
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.ConnectionError:
                print(f"Could not connect to node: {node}")
            except Exception as e:
                print(f"An error occurred with node {node}: {e}")

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_food_supply_transaction(self, sender, recipient, amount, food_item_id, producer, location, event_type, temperature_log=None, certification_info=None, destination=None, quantity=None, notes=None):
        """
        Creates a new transaction for a food supply chain event
        :param sender: Identifier of the entity sending (e.g., previous handler)
        :param recipient: Identifier of the entity receiving (e.g., next handler)
        :param amount: A general numerical value (e.g., payment, or placeholder if quantity is specific)
        :param food_item_id: Unique identifier for the specific batch/item of food
        :param producer: The original producer or current handler of the food
        :param location: Current physical location of the food item
        :param event_type: Type of event (e.g., 'Harvested', 'Processed', 'Shipped', 'Received', 'Inspected')
        :param temperature_log: (Optional) Temperature data for perishable goods
        :param certification_info: (Optional) Relevant quality/safety certifications
        :param destination: (Optional) Where the food is headed next
        :param quantity: (Optional) Amount of food, if 'amount' is for value
        :param notes: (Optional) Additional notes about the transaction/event
        :return: The index of the Block that will hold this transaction
        """
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'food_item_id': food_item_id,
            'producer': producer,
            'location': location,
            'event_type': event_type,
            'timestamp': time(), # Timestamp for the transaction itself
        }
        if temperature_log:
            transaction['temperature_log'] = temperature_log
        if certification_info:
            transaction['certification_info'] = certification_info
        if destination:
            transaction['destination'] = destination
        if quantity is not None:
            transaction['quantity'] = quantity
        if notes:
            transaction['notes'] = notes

        self.current_transactions.append(transaction)

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
        :param last_proof: <int> Previous proof
        :param proof: <int> Current proof
        :return: <boolean> True if correct, False otherwise.
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"