# Parameter names are fixed by upstream LaZer scripts/lin-codegen.sage.
# Module-LWE receiver-key relation params (q=12289, eta=2 CBD); distinct from the
# ballot-field params in ballot-field-linear-params.py.
vname = "receiver_key_param"
deg = 256  # statement ring degree
mod = 12289  # NTT-friendly Module-LWE modulus q
dim = (4, 8)  # statement matrix shape: 4 rows x 8 columns
wpart = [list(range(0, 8))]
wl2 = [sqrt(8192)]  # witness L2 bound = sqrt(8192)
wbin = [0]
wrej = [0]
wlinf = 2  # witness infinity-norm bound (eta=2)
