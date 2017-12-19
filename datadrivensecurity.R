## Needed packages installation
#install.packages("devtools")
#install.packages("tidyr")
#install.packages("dplyr")
#install.packages("stringr")
#install.packages("foreach")

##Shodan package expects SHODAN_API_KEY to be defined
#devtools::install_github("hrbrmstr/shodan")

##Load packages
library(shodan)
library(dplyr)
library(stringr)
library(tidyr)
library(foreach)

##Download sysdata file that contains CVEs and CPEs information
download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda", destfile = "sysdata.rda")

##Load sysdata file
load("sysdata.rda")

##Create new lists with CVEs information
cpes <- netsec.data$datasets$cpes
cves <- netsec.data$datasets$cves

##Create vector with camera vendors that will be checked to create the research
search_cameras <- c("axis.*?camera","axis.*?neteye" , "d-link.*?camera", "mobotix.*?camera")
cpe_fields <- c("cpe", "type", "vendor", "model", "version")
cve_selected_fields <- c("cve", "cvss", "description", "cpe.software")

##Get cameras information
cameras <- data.frame(cves %>% filter(str_detect(cpe.software, paste(search_cameras, collapse = "|"))) %>% select(cve_selected_fields))

##Define a new empty data frame
cameras_data <- data.frame(cve = character(), cvss = double(), description = character(), type = character(), vendor = character(), model = character(), version = character())

##Get the CPE software information and create a new dataframe with the information that is related to cameras
for (row in 1:nrow(cameras)) {
  camera <- cameras[row,]
  
  ##Parse cpe.software to JSON and filter its information in order to extract only camera related information
  ##Once filtered, separate fields in cpe fields: cpe, type, vendor, model and version
  software_list <- data.frame(software = jsonlite::fromJSON(camera$cpe.software), stringsAsFactors = FALSE) %>% filter(str_detect(software, paste(search_cameras, collapse = "|"))) %>% separate(software, cpe_fields, sep = ":")
  
  cameras_data = rbind(cameras_data, data.frame(camera[1:3], software_list[2:5])) 
}


