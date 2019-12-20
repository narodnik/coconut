from coconut import scheme as coconut

# Coconut

def prepare_blind_sign(params, attributes):
    (d, gamma) = coconut.elgamal_keygen(params)
    lambda_ = coconut.prepare_blind_sign(params, gamma, attributes, public_m=[])
    return (d, gamma, lambda_)

def blind_sign(params, secret_keys, gamma, lambda_):
    signatures_tilde = [coconut.blind_sign(params, secret_key, gamma, lambda_,
                                           public_m=[])
                        for secret_key in secret_keys]
    return signatures_tilde

def unblind(params, signatures_tilde, d):
    signatures = [coconut.unblind(params, sigma_tilde, d)
                  for sigma_tilde in signatures_tilde]
    return signatures

def issue_credential(params, attributes, secret_keys):
    (d, gamma, lambda_) = prepare_blind_sign(params, attributes)

    signatures_tilde = blind_sign(params, secret_keys, gamma, lambda_)

    signatures = unblind(params, signatures_tilde, d)
    signature = coconut.agg_cred(params, signatures)
    return signature

def prove_credential(params, verify_key, attributes, credential, extra_proof):
    return coconut.prove_cred(params, verify_key, credential, attributes,
                              extra_proof)

def verify_credential(params, verify_key, proof, extra_proof):
    return coconut.verify_cred(params, verify_key, proof,
                               extra_proof=extra_proof)

# Colada

def deposit(params, value, secret_keys):
    (G, o, g1, hs, g2, e) = params
    serial_number = o.random()
    attributes = [value, serial_number]
    credential = issue_credential(params, attributes, secret_keys)
    return serial_number, credential

class SignWithdrawProof:

    def __init__(self, params, serial_number):
        self.params = params
        self.serial_number = serial_number

        (G, o, g1, hs, g2, e) = self.params
        self.serial_witness = o.random()

        self.witness_commits = [self.serial_witness * g1]
        self.base_points = [g1]

    def compute_responses(self, challenge):
        (G, o, g1, hs, g2, e) = self.params
        response = (self.serial_witness - challenge * self.serial_number) % o
        return [self.serial_witness - challenge * self.serial_number]

class VerifyWithdrawProof:

    def __init__(self, params, serial_commit):
        self.params = params
        self.serial_commit = serial_commit

        (G, o, g1, hs, g2, e) = self.params
        self.base_points = [g1]

    def recompute_witness(self, challenge, responses):
        (G, o, g1, hs, g2, e) = self.params
        assert len(responses) == 1
        response = responses[0]

        witness_commit = challenge * self.serial_commit + response * g1
        return [witness_commit]

def request_withdraw(params, verify_key, attributes, credential):
    (G, o, g1, hs, g2, e) = params
    value, serial = attributes
    serial_commit = serial * g1

    withdraw_proof = SignWithdrawProof(params, serial)
    proof = prove_credential(params, verify_key, attributes, credential,
                             withdraw_proof)
    return proof, serial_commit

spent_serials = []

def accept_withdraw(params, verify_key, withdraw_request, crypto_address):
    proof, serial_commit = withdraw_request

    if serial_commit in spent_serials:
        print("Error: Credential already spent")
        return False

    withdraw_proof = VerifyWithdrawProof(params, serial_commit)
    success = verify_credential(params, verify_key, proof, withdraw_proof)

    if not success:
        print("Error: Proof verification failed")
        return False

    spent_serials.append(serial_commit)
    print("Sent", crypto_address)

    return True

def main():
    number_attributes = 2
    params = coconut.setup(number_attributes)

    threshold_authorities, number_authorities = 5, 7
    (secret_keys, verify_keys) = \
        coconut.ttp_keygen(params, threshold_authorities, number_authorities)
    verify_key = coconut.agg_key(params, verify_keys)

    value_deposit = 110
    serial_number, credential = deposit(params, value_deposit, secret_keys)

    withdraw_request = request_withdraw(params, verify_key,
                                        [value_deposit, serial_number],
                                        credential)

    assert accept_withdraw(params, verify_key, withdraw_request, "1crypto")

if __name__ == "__main__":
    main()

