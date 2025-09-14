library(Rserve)

test <- "test.c"

if (test == "demo.c") {
  # Default server, no auth, no OCAP
  Rserve(debug = TRUE)
} else if (test == "test.c") {
  # Server with auth (no encryption)
  Rserve(debug = TRUE, args = "--RS-set auth=1 --RS-set plaintext=1 --RS-set pwdfile=/home/byron/Documents/scratchpad/rsrv-client/test/rserve/password.txt")
} else if (test == "ocap.c") {
  # Server with OCAP
  Rserve(debug = TRUE, args = "--RS-set qap.oc=1 --RS-set source=/home/byron/Documents/scratchpad/rsrv-client/test/rserve/ocap.R")
}
