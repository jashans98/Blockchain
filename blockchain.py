from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5


def verify_signature(sender, message, signature):
    return sender.get_public_verifier().verify(SHA.new(message), signature)


class BlockChain(object):
    def __init__(self):
        self.genesis_hash_pointer = None
        self.block_hashes = {}
        self.current_id = 0

    def next_id(self):
        self.current_id += 1
        return self.current_id

    def verify_transaction(self, transaction):
        if type(transaction) is CreateCoinTransaction:
            return True

        elif type(transaction) is TransferCoinTransaction:
            transfer_coin = transaction.sender.peek_coin()  # the hash of the block where the coin was created
            prev_block = self.block_hashes[transfer_coin]

            if self.validate_spend_and_tamper(transfer_coin):
                return False

            if not verify_signature(prev_block.transaction.receiver, transaction.message, transaction.signature):
                return False

            return True

    def validate_spend_and_tamper(self, hash_code):
        hash_pointer = self.genesis_hash_pointer
        while hash_pointer is not None:
            block = hash_pointer.block
            if not block.hash_code() == hash_pointer.expected_hash:
                print('tampered block')
                return True

            if type(block.transaction) is TransferCoinTransaction and block.transaction.coin == hash_code:
                print('coin has been spent already')
                return True

            hash_pointer = block.prev_hash_pointer

        return False

    def add_transaction(self, transaction):
        if self.verify_transaction(transaction):
            new_block = Block(self.genesis_hash_pointer, transaction, self.next_id())
            self.genesis_hash_pointer = HashPointer(new_block.hash_code(), new_block)
            self.block_hashes[new_block.hash_code()] = new_block

            transaction.receiver.add_coin(new_block.hash_code())

            if type(transaction) is TransferCoinTransaction:
                transaction.sender.remove_coin()


class HashPointer(object):
    def __init__(self, hash_code, block):
        self.expected_hash = hash_code
        self.block = block

    def __eq__(self, other):
        return self.expected_hash == other.expected_hash


class Block(object):
    def __init__(self, prev_hash_pointer, transaction, block_id):
        self.prev_hash_pointer = prev_hash_pointer
        self.transaction = transaction
        self.id = block_id

    def hash_code(self):
        return SHA.new(str(self)).hexdigest()

    def __str__(self):
        return '%s: %s' % (self.id, str(self.transaction))


class CreateCoinTransaction(object):
    def __init__(self, receiver):
        self.receiver = receiver

    def __str__(self):
        return 'give coin to %s' % str(self.receiver)


class TransferCoinTransaction(object):
    def __init__(self, sender, receiver):
        self.sender = sender
        self.coin = sender.peek_coin()
        self.receiver = receiver
        self.signature = None
        self.message = str(self)

    def add_signature(self, signature):
        self.signature = signature

    def __str__(self):
        return '%s transfers %s to %s' % (self.sender, self.coin, self.receiver)


class BlockUser(object):
    def __init__(self):
        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey()
        self.signer = PKCS1_v1_5.new(self.private_key)
        self.verifier = PKCS1_v1_5.new(self.public_key)

        # this isn't strictly necessary for the blockchain to function
        # it just makes it much easier to transfer coins when we can directly see who owns it
        self.coins = []

    def get_public_key(self):
        return self.public_key

    def get_public_verifier(self):
        return self.verifier

    def add_coin(self, coin):
        self.coins.append(coin)

    def remove_coin(self):
        if not self.coins:
            raise ValueError('user has no coins')

        return self.coins.pop(0)

    def peek_coin(self):
        if not self.coins:
            raise ValueError('Owner has no coins')

        return self.coins[0]

    def sign(self, message):
        return self.signer.sign(SHA.new(message))

    def __str__(self):
        return self.public_key.exportKey()


# run some tests
if __name__ == '__main__':
    chain = BlockChain()
    jashan = BlockUser()
    hitesh = BlockUser()

    t1 = CreateCoinTransaction(jashan)
    chain.add_transaction(t1)

    t2 = CreateCoinTransaction(hitesh)
    chain.add_transaction(t2)
