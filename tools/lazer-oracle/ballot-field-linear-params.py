from sage.all import sqrt

# Variable names (vname/deg/mod/dim/wpart/wl2/wbin/wrej/wlinf) are fixed by upstream
# LaZer lin-codegen.sage and must not be renamed.
vname = "ballot_field_param"
deg = 64  # proof-system ring degree
mod = 65537  # GF(65537) field modulus
dim = (70, 176)  # statement matrix shape: 70 rows x 176 columns
wpart = [list(range(0, 176))]
wl2 = [sqrt(65536)]  # witness L2 bound = sqrt(65536) = 256
wbin = [0]
wrej = [0]
wlinf = 16  # witness infinity-norm bound
