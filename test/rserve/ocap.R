library(Rserve)

parse_eval <- function(s) {
  tryCatch(eval(parse(text = s), .GlobalEnv),
           error = function(e) e)
}

auth <- function(user, pass) {
  if (user == "mike" && pass == "mypwd")
    list(parse_eval = ocap(parse_eval))
  else
    "sorry, unauthorized!"
}

oc.init <- function() ocap(auth)
