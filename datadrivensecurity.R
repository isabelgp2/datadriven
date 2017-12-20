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
search_cameras <- c("axis.*?camera","axis.*?neteye" , "d-link.*?camera", "mobotix.*?camera", "cisco.*?camera", "canon.*?camera", "vivotek.*?camera", "y-cam", "sony.*?camera")
cpe_fields <- c("cpe", "type", "vendor", "model", "version")
cve_selected_fields <- c("cve", "cvss", "description", "cpe.software")
special_chars_to_remove <- c("_", "%")

##Get CVE cameras information
cameras <- data.frame(cves %>% filter(str_detect(cpe.software, paste(search_cameras, collapse = "|"))) %>% select(cve_selected_fields))

##Define a new empty data frame
cameras_data <- data.frame(cve = character(), cvss = double(), description = character(), type = character(), vendor = character(), model = character(), version = double())

##Get the CPE software information and create a new dataframe with the information that is related to cameras
for (row in 1:nrow(cameras)) {
  camera <- cameras[row,]
  
  ##Parse cpe.software to JSON and filter its information in order to extract only camera related information
  ##Once filtered, separate fields in cpe fields: cpe, type, vendor, model and version
  software_list <- data.frame(software = jsonlite::fromJSON(camera$cpe.software), stringsAsFactors = FALSE) %>% filter(str_detect(software, paste(search_cameras, collapse = "|"))) %>% separate(software, cpe_fields, sep = ":") %>% drop_na() %>% filter(type == "/h") %>% filter(version != "-")
  
  if (nrow(software_list)[1] > 0){
    ##Remove special chars
    software_list$model <- gsub(paste(special_chars_to_remove, collapse = "|"), ' ', software_list$model)
    
    cameras_data = rbind(cameras_data, data.frame(camera[1:3], software_list[2:5])) 
  }
}

##Create a search data frame that will be used for shodan searches
shodan_search_list <- select(cameras_data, cpe_fields[3:5]) %>% distinct()

shodan_cameras_data <- NULL

for (row in 1:nrow(shodan_search_list)) {
  ##Get camera information
  camera_info <- shodan_search_list[row,]
  
  ##Get query by joining vendor, model and version fields
  shodan_query <- (unite(camera_info, "software", vendor, model, version, sep = " "))$software
  
  ##Shodan result
  result <- shodan_search(query = shodan_query)
  ##If shodan result is not empty, add its information to our shodan_camera_data dataframe
  if (length(result$matches)[1] > 0) {
    shodan_cameras_data = rbind(shodan_cameras_data, data.frame(vendor = camera_info$vendor, model = camera_info$mode, version = camera_info$version, countruy_code = result$matches$location$country_code, country_name = result$matches$location$country_name, latitude = result$matches$location$latitude, longitude = result$matches$location$longitude, ip_str = result$matches$ip_str, data = result$matches$data, stringsAsFactors = FALSE))
  }
  
  ##Wait 0.5 sec after every search to avoid HTTP 503 sever errors
  Sys.sleep(0.5)
}

test <- left_join(shodan_cameras_data, cameras_data)

