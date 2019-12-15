from coconut import scheme as coconut

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

def deposit(params, value, secret_keys):
    (G, o, g1, hs, g2, e) = params
    serial_number = o.random()
    attributes = [value, serial_number]
    credential = issue_credential(params, attributes, secret_keys)
    return serial_number, credential

def prove_credential(params, verify_key, attributes, credential):
    return coconut.prove_cred(params, verify_key, credential, attributes)

def withdraw(verify_key, attributes, credential, address):
    proof = prove_credential(params, verify_key,
                             [110, serial_number], credential)

def main():
    number_attributes = 2
    params = coconut.setup(number_attributes)

    threshold_authorities, number_authorities = 5, 7
    (secret_keys, verify_keys) = \
        coconut.ttp_keygen(params, threshold_authorities, number_authorities)
    verify_key = coconut.agg_key(params, verify_keys)

    serial_number, credential = deposit(params, 110, secret_keys)

if __name__ == "__main__":
    main()

