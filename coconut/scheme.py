""" 
Coconut threshold credentials scheme. 
Example:
	>>> q = 7 # maximum number of attributes
	>>> private_m = [10] * 2 # private attributes
	>>> public_m = [3] * 1 # public attributes
	>>> t, n = 2, 3 # threshold parameter and number of authorities
	>>> params = setup(q)
	>>> (d, gamma) = elgamal_keygen(params) # El-Gamal keypair
	
	>>> # generate commitment and encryption
	>>> Lambda = prepare_blind_sign(params, gamma, private_m, public_m=public_m)

	>>> # generate key
	>>> (sk, vk) = ttp_keygen(params, t, n)

	>>> # aggregate verification keys
	>>> aggr_vk = agg_key(params, vk)

	>>> # bind sign
	>>> sigs_tilde = [blind_sign(params, ski, gamma, Lambda, public_m=public_m) for ski in sk]

	>>> # unblind
	>>> sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]

	>>> # aggregate credentials
	>>> sigma = agg_cred(params, sigs)

	>>> # randomize credentials and generate any cryptographic material to verify them
	>>> Theta = prove_cred(params, aggr_vk, sigma, private_m)

	>>> # verify credentials
	>>> assert verify_cred(params, aggr_vk, Theta, public_m=public_m)
"""
from bplib.bp import BpGroup, G2Elem
from coconut.utils import *
from coconut.proofs import *


def setup(q=1):
	"""
	Generate the public parameters. 

	Parameters:
		- `q` (integer): the maximum number of attributes that can be embbed in the credentials

	Returns:
		- params: the publc parameters
	"""
	assert q > 0
	G = BpGroup()
	(g1, g2) = G.gen1(), G.gen2()
	hs = [G.hashG1(("h%s" % i).encode("utf8")) for i in range(q)]
	(e, o) = G.pair, G.order()
	return (G, o, g1, hs, g2, e)


def ttp_keygen(params, t, n):
    """
        Generate keys for threshold credentials (executed by a TTP). This protocol can however be executed in a distributed way as illustrated by the following link: https://crysp.uwaterloo.ca/software/DKG/

    Parameters:
        - `params`: public parameters generated by `setup`
        - `t` (integer): the threshold parameter
        - `n` (integer): the total number of authorities

    Returns:
        - `sk` [(Bn, [Bn])]: array containing the secret key of each authority
        - `vk` [(G2Elem, G2Elem, [G2Elem])]: array containing the verification key of each authority
    """
    (G, o, g1, hs, g2, e) = params
    q = len(hs)
    assert n >= t and t > 0 and q > 0
    # generate polynomials
    v = [o.random() for _ in range(0,t)]
    w = [[o.random() for _ in range(0,t)] for _ in range(q)]
    # generate shares
    x = [poly_eval(v,i) % o for i in range(1,n+1)]
    y = [[poly_eval(wj,i) % o for wj in w] for i in range(1,n+1)]
    # set keys
    sk = list(zip(x, y))
    vk = [(g2, x[i]*g2, [y[i][j]*g2 for j in range(len(y[i]))]) for i in range(len(sk))]
    return (sk, vk)


def keygen(params):
    """
        Generate the secret and verification keys for an authority. This protocol cannot be used for threshold setting.
        
        Parameters:
        - `params`: public parameters generated by `setup`
        
        Returns:
        - `sk` (Bn, [Bn]): secret key of the authority
        - `vk` (G2Elem, G2Elem, [G2Elem]): verification key of the authority
    """
    (G, o, g1, hs, g2, e) = params
    q = len(hs)
    x = o.random()
    y = [o.random() for _ in range(q)]
    sk = (x, y)
    vk = (g2, x*g2, [yi*g2 for yi in y])
    return (sk, vk)


def agg_key(params, vks, threshold=True):
    """
    Aggregate the verification keys.

    Parameters:
        - `params`: public parameters generated by `setup`
        - `vks` [(G2Elem, G2Elem, [G2Elem])]: array containing the verification key of each authority
        - `threshold` (bool): optional, whether to use threshold cryptography or not

    Returns:
        - `aggr_vk`: aggregated verification key
    """
    (G, o, g1, hs, g2, e) = params
    # filter missing keys (in the threshold setting)
    filter = [vks[i] for i in range(len(vks)) if vks[i] is not None]
    indexes = [i+1 for i in range(len(vks)) if vks[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o) if threshold else [1 for _ in range(len(vks))]
    # aggregate keys
    (_, alpha, beta) = zip(*filter)
    q = len(beta[0])
    aggr_alpha = ec_sum([l[i]*alpha[i] for i in range(len(filter))])
    aggr_beta = [ec_sum([l[i]*beta[i][j] for i in range(len(filter))]) for j in range(q)]
    aggr_vk = (g2, aggr_alpha, aggr_beta)
    return aggr_vk


def prepare_blind_sign(params, gamma, private_m, public_m=[],
                       extra_proof=ExtraProof()):
    """
    Build cryptographic material for blind sign.

    Parameters:
        - `params`: public parameters generated by `setup`
        - `gamma` (G1Elem): the user's El-Gamal public key
        - `private_m` [Bn]: array containing the private attributes
        - `public_m` [Bn]: optional, array containing the public attributes

    Returns:
        - `Lambda`: commitments and encryptions to the attributes
    """
    assert len(private_m) > 0
    (G, o, g1, hs, g2, e) = params
    attributes = private_m + public_m
    assert len(attributes) <= len(hs)
    # build commitment
    r = o.random()
    cm = r*g1 + ec_sum([attributes[i]*hs[i] for i in range(len(attributes))])
    # build El Gamal encryption
    h = G.hashG1(cm.export())
    enc = [elgamal_enc(params, gamma, m, h) for m in private_m]
    (a, b, k) = zip(*enc)
    c = list(zip(a, b))
    # build proofs
    pi_s = make_pi_s(params, gamma, c, cm, k, r, public_m, private_m,
                     extra_proof)
    Lambda = (cm, c, pi_s)
    return Lambda


def blind_sign(params, sk, gamma, Lambda, public_m=[],
               extra_proof=ExtraProof()):
    """
    Blindly sign private attributes.

    Parameters:
        - `params`: public parameters generated by `setup`
        - `sk` (Bn, Bn): the secret key of the authority
        - `gamma` (G1Elem): the user's El-Gamal public key
        - `Lambda`: commitments and encryptions to the attributes
        - `public_m` [Bn]: optional, array containing the public attributes

    Returns:
        - `sigma_tilde`: blinded credential
    """
    (G, o, g1, hs, g2, e) = params
    (x, y) = sk
    (cm, c, pi_s) = Lambda
    (a, b) = zip(*c)
    assert (len(c)+len(public_m)) <= len(hs)
    # verify proof of correctness
    assert verify_pi_s(params, gamma, c, cm, pi_s, extra_proof)
    # issue signature
    h = G.hashG1(cm.export())
    t1 = [mi*h for mi in public_m]
    t2 = ec_sum([yi*ai for yi,ai in zip(y,a)])
    t3 = x*h + ec_sum([yi*bi for yi,bi in zip(y,list(b)+t1)])
    sigma_tilde = (h, (t2, t3))
    return sigma_tilde


def unblind(params, sigma_tilde, d):
	""" 
	Unblind the credentials. 

	Parameters:
		- `params`: public parameters generated by `setup`
		- `sigma_tilde`: blinded credential
		- `d`: user's El-Gamal private key

	Returns:
		- `sigma`: unblinded credential
	"""
	(h, c_tilde) = sigma_tilde
	sigma = (h, elgamal_dec(params, d, c_tilde))
	return sigma


def agg_cred(params, sigs, threshold=True):
    """
    Aggregate partial credentials.

    Parameters:
        - `params`: public parameters generated by `setup`
        - `sigs` [(G1Elem, G1Elem)]: array of ordered partial credentials, include `None` if a partial credential is missing (in the threshold setting)
        - `threshold` (bool): optional, whether to use threshold cryptography or not

    Returns:
        - `aggr_sigma`: aggregated credential
    """
    (G, o, g1, hs, g2, e) = params
    # filter missing credentials (in the threshold setting)
    filter = [sigs[i] for i in range(len(sigs)) if sigs[i] is not None]
    indexes = [i+1 for i in range(len(sigs)) if sigs[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o) if threshold else [1 for _ in range(len(sigs))]
    # aggregate sigature
    (h, s) = zip(*filter)
    aggr_s = ec_sum([l[i]*s[i] for i in range(len(filter))])
    aggr_sigma = (h[0], aggr_s)
    return aggr_sigma


def prove_cred(params, aggr_vk, sigma, private_m, extra_proof=ExtraProof()):
    """
    Build cryptographic material for blind verify.

    Parameters:
        - `params`: public parameters generated by `setup`
        - `aggr_vk`: aggregated verification key
        - `sigma`: credential
        - `private_m` [Bn]: array containing the private attributes

    Returns:
        - `Theta`: randomized credential and cryptographic material to verify them
    """
    assert len(private_m) > 0
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, beta) = aggr_vk
    (h, s) = sigma
    assert len(private_m) <= len(beta)
    r_prime = o.random()
    (h_prime , s_prime) = (r_prime*h , r_prime*s)
    sigma_prime =(h_prime, s_prime)
    r = o.random()
    kappa = r*g2 + alpha + ec_sum([private_m[i]*beta[i] for i in range(len(private_m))])
    nu = r*h_prime
    pi_v = make_pi_v(params, aggr_vk, sigma_prime, private_m, r, extra_proof)
    Theta = (kappa, nu, sigma_prime, pi_v)
    return Theta


def verify_cred(params, aggr_vk, Theta, public_m=[], extra_proof=ExtraProof()):
    """
    Verify credentials.

    Parameters:
        - `params`: public parameters generated by `setup`
        - `aggr_vk`: aggregated verification key
        - `Theta`: credential and cryptographic material to verify them
        - `public_m` [Bn]: optional, array containing the public attributes

    Returns:
        - `ret` (bool): whether the credential verifies
    """
    (G, o, g1, hs, g2, e) = params
    (g2, _, beta) = aggr_vk
    (kappa, nu, sigma, pi_v) = Theta
    (h, s) = sigma
    private_m_len = len(pi_v[1])
    assert len(public_m)+private_m_len <= len(beta)
    # verify proof of correctness
    assert verify_pi_v(params, aggr_vk, sigma, kappa, nu, pi_v, extra_proof)
    # add clear text messages
    aggr = G2Elem.inf(G)
    if len(public_m) != 0:
        aggr = ec_sum([public_m[i]*beta[i+private_m_len] for i in range(len(public_m))])
    # verify
    return not h.isinf() and e(h, kappa+aggr) == e(s+nu, g2)


