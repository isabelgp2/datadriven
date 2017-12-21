## Needed packages installation
#install.packages("devtools")
#install.packages("tidyr")
#install.packages("dplyr")
#install.packages("stringr")
#install.packages("foreach")
#install.packages("gsubfn")

##Shodan package expects SHODAN_API_KEY to be defined
#devtools::install_github("hrbrmstr/shodan")

##Load packages
library(shodan)
library(dplyr)
library(stringr)
library(tidyr)
library(foreach)
library(gsubfn)

##Download sysdata file that contains CVEs and CPEs information
download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda", destfile = "sysdata.rda")

##Load sysdata file
load("sysdata.rda")

##Create new lists with CVEs information
cpes <- netsec.data$datasets$cpes
cves <- netsec.data$datasets$cves

##Create vector with camera vendors that will be checked to create the research
cve_search_list <- c("axis.*?camera", "d-link.*?camera", "tp-link.*?sc", "canon.*?camera", "vivotek.*?camera", "sony.*?camera")
shodan_search_list <- c("axis camera", "d-link dcs", "tp-link ip-camera", "canon network camera", "vivotek camera", "sony camera")
regex_camera_search <- list(axis = "((AXIS|Axis).*Camera.(\\w)+(.(\\d)+)+)", dlink = "(DCS-(\\d)+\\w)", tplink = "TP-Link IP-Camera", canon = "Canon Network Camera", vivotek = "Vivotek Network Camera", sony = "((SONY|Sony).Network Camera.(\\w)+-(\\w)+)")

cpe_fields <- c("cpe", "type", "vendor", "model", "version")
cve_selected_fields <- c("cve", "cvss", "description", "cpe.software")
special_chars_to_remove <- c("_", "%")

##Get CVE cameras information
cameras <- data.frame(cves %>% filter(str_detect(cpe.software, paste(cve_search_list, collapse = "|"))) %>% select(cve_selected_fields))

##Define a new empty data frame
cve_cameras_data <- data.frame(cve = character(), cvss = double(), description = character(), type = character(), vendor = character(), model = character(), version = double())

##Get the CPE software information and create a new dataframe with the information that is related to cameras
for (row in 1:nrow(cameras)) {
  camera <- cameras[row,]
  
  ##Parse cpe.software to JSON and filter its information in order to extract only camera related information
  ##Once filtered, separate fields in cpe fields: cpe, type, vendor, model and version
  software_list <- data.frame(software = jsonlite::fromJSON(camera$cpe.software), stringsAsFactors = FALSE) %>% filter(str_detect(software, paste(cve_search_list, collapse = "|"))) %>% separate(software, cpe_fields, sep = ":") %>% drop_na() %>% filter(type == "/h")
  
  if (nrow(software_list)[1] > 0) {
    ##Remove special chars
    software_list$model <- gsub(paste(special_chars_to_remove, collapse = "|"), ' ', software_list$model)
    
    cve_cameras_data = rbind(cve_cameras_data, data.frame(camera[1:3], software_list[2:5])) 
  }
}

parse_axis_camera <- function(software_info){
  for (i in 1:nrow(software_info)) {
    rgx <- strapply(software_info[i,]$data, regex_camera_search["axis"])
    if (length(rgx) > 0 && !is.null(rgx[[1]])) {
      info <- strsplit(unlist(rgx), " ")
      if (length(info) > 0) {
        info <- info[[1]]
        software_info[i,]$vendor <- "axis"
        software_info[i,]$model <- tolower(paste(info[2:(length(info)-1)], collapse = " "))
        software_info[i,]$version <- info[length(info)]
      }
    }
  }
  software_info
}

parse_sony_camera <- function(software_info){
  for (i in 1:nrow(software_info)) {
    rgx <- strapply(software_info[i,]$data, regex_camera_search["sony"])
    if (length(rgx) > 0 && !is.null(rgx[[1]])) {
      info <- strsplit(unlist(rgx), " ")
      if (length(info) > 0) {
        info <- info[[1]]
        software_info[i,]$vendor <- "sony"
        software_info[i,]$model <- tolower(paste(info[2:(length(info)-1)], collapse = " "))
        software_info[i,]$version <- info[length(info)]
      }
    }
  }
  software_info
}

parse_dlink_camera <- function(software_info){
  for (i in 1:nrow(software_info)) {
    rgx <- strapply(software_info[i,]$data, regex_camera_search["dlink"])
    if (length(rgx) > 0 && !is.null(rgx[[1]])) {
        info <- rgx[[1]]
        software_info[i,]$vendor <- "d-link"
        software_info[i,]$model <- tolower(info[1])
    }
  }
  software_info
}

get_camera_software <- function(software_info, shodan_query){
  if (shodan_query == shodan_search_list[1]) {
    software_info <- parse_axis_camera(software_info)
  } else if (shodan_query == shodan_search_list[2]) {
    software_info <- parse_dlink_camera(software_info)
  } else if (shodan_query == shodan_search_list[3]) {
    software_info$vendor <- "tp-link"
    software_info$model <- "ip-camera"
  } else if (shodan_query == shodan_search_list[4]) {
    software_info$vendor <- "canon"
    software_info$model <- "network camera"
  } else if (shodan_query == shodan_search_list[5]) {
    software_info$vendor <- "vivotek"
    software_info$model <- "network camera"
  } else if (shodan_query == shodan_search_list[6]) {
    software_info <- parse_sony_camera(software_info)
  }
  
  software_info
}

shodan_search_function <- function(shodan_query) {
  result_to_return <- NULL
  result <- shodan_search(query = shodan_query)
  
  # if (result$total > 100) {
  #   result_to_return = rbind(result_to_return, data.frame(countruy_code = result$matches$location$country_code, country_name = result$matches$location$country_name, latitude = result$matches$location$latitude, longitude = result$matches$location$longitude, ip_str = result$matches$ip_str, data = result$matches$data, stringsAsFactors = FALSE))
  #   
  #   for (i in 2:round(result$total/100)) {
  #     result <- shodan_search(query = shodan_query, page = i)
  #     result_to_return = rbind(result_to_return, data.frame(countruy_code = result$matches$location$country_code, country_name = result$matches$location$country_name, latitude = result$matches$location$latitude, longitude = result$matches$location$longitude, ip_str = result$matches$ip_str, data = result$matches$data, vendor = "", model = "", version = "", stringsAsFactors = FALSE))
  #     print(i)
  #   }
  # } else {
    result_to_return <- data.frame(country_code = result$matches$location$country_code, country_name = result$matches$location$country_name, latitude = result$matches$location$latitude, longitude = result$matches$location$longitude, ip_str = result$matches$ip_str, data = result$matches$data, vendor = "", model = "", version = "", stringsAsFactors = FALSE)
  #}
  
  get_camera_software(result_to_return, shodan_query)
}


shodan_cameras_data <- NULL
for (i in 1:length(shodan_search_list)) {
  shodan_cameras_data = rbind(shodan_cameras_data, shodan_search_function(shodan_search_list[i]))
}

test2 <- left_join(shodan_cameras_data, cve_cameras_data)
