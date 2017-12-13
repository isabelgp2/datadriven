#Install shodan packate, uncomment if needed
#devtools::install_github("hrbrmstr/shodan")
#Shodan package expects SHODAN_API_KEY to be defined

#Load shodan library
library(shodan)

#Download sysdata file that contains CVEs and CPEs information
download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda", "sysdata.rda")

#Load sysdata file
load("sysdata.rda")

# Create new lists with CPEs and CVEs information
cpes <- netsec.data$datasets$cpes
cves <- netsec.data$datasets$cves




