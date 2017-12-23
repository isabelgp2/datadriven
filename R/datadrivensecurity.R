#' Download CVE data
#' 
#' Download CVE data information from https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda.
#' @return CVE data frame

downloadCVEData <- function() {
  ##Download sysdata file that contains CVEs and CPEs information
  download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda", destfile = "sysdata.rda")
  
  ##Load sysdata file
  load("sysdata.rda")
  
  ##Create new lists with CVEs information
  cves <- netsec.data$datasets$cves
  
  ##Return new CVEs fata frame
  return(cves)
}

#' Get data frame with CVEs information related to cameras vulnerabilities
#' 
#' @param  cves, entire list of CVEs
#' @return cve_cameras_data, data frame with CVEs

getVulnerableCamerasCVEs <- function(cves){
  
  ##Create vector with camera vendors that will be checked to create the research
  cve_search_list <- c("axis.*?camera", "d-link.*?camera", "tp-link.*?sc", "canon.
                       *?camera", "vivotek.*?camera", "sony.*?camera")
  
  cpe_fields <- c("cpe", "type", "vendor", "model", "version")
  cve_selected_fields <- c("cve", "cvss", "description", "cpe.software")
  special_chars_to_remove <- c("_", "%")
  
  ##Get CVE cameras information
  cameras <- data.frame(cves %>% filter(str_detect(cpe.software, paste(cve_search_list, collapse = "|"))) %>% select(cve_selected_fields))
  
  ##Define a new empty data frame
  cve_cameras_data <- data.frame(cve = character(), 
                                 cvss = double(), 
                                 description = character(), 
                                 type = character(), 
                                 vendor = character(), 
                                 model = character(), 
                                 version = double())
  
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
  
  cve_cameras_data
}


#' Parse AXIS camera information got from Shodan searches
#' 
#' @param software_info, list with shodan searches
#' @param regex_camera_search, regex experssion used to parse AXIS cameras information
#' 
#' @return software_info data frame with extra information for vendor, model and version

parseAxisCamera <- function(software_info, regex_camera_search){
  for (i in 1:nrow(software_info)) {
    rgx <- strapply(software_info[i,]$data, regex_camera_search)
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

#' Parse Sony camera information got from Shodan searches
#' 
#' @param software_info, list with shodan searches
#' @param regex_camera_search, regex experssion used to parse Sony cameras information
#' 
#' @return software_info data frame with extra information for vendor, model and version

parseSonyCamera <- function(software_info, regex_camera_search){
  for (i in 1:nrow(software_info)) {
    rgx <- strapply(software_info[i,]$data, regex_camera_search)
    if (length(rgx) > 0 && !is.null(rgx[[1]])) {
      info <- strsplit(unlist(rgx), " ")
      if (length(info) > 0) {
        info <- info[[1]]
        software_info[i,]$vendor <- "sony"
        software_info[i,]$model <- tolower(paste(info[2:(length(info)-1)], collapse = " "))
        software_info[i,]$version <- tolower(info[length(info)])
      }
    }
  }
  software_info
}

#' Parse D-Link camera information got from Shodan searches
#' 
#' @param software_info, list with shodan searches
#' @param regex_camera_search, regex experssion used to parse AXIS cameras information
#' 
#' @return software_info data frame with extra information for vendor, model and version

parseDlinkCamera <- function(software_info, regex_camera_search){
  for (i in 1:nrow(software_info)) {
    rgx <- strapply(software_info[i,]$data, regex_camera_search)
    if (length(rgx) > 0 && !is.null(rgx[[1]])) {
        info <- rgx[[1]]
        software_info[i,]$vendor <- "d-link"
        software_info[i,]$model <- tolower(info[1])
    }
  }
  software_info
}

#' Apply parsing functions depending on the camera facturer
#' 
#' @param software_info, list with shodan searches
#' @param shodan_query, value of the query used when searching with Shodan
#' 
#' @return software_info data frame with extra information of vendor, model and version

getCameraSoftware <- function(software_info, shodan_query){
  shodan_search_list <- c("axis camera", "d-link dcs", "tp-link ip-camera", 
                          "canon network camera", "vivotek camera", "sony camera")
  
  regex_camera_search <- list(axis = "((AXIS|Axis).*Camera.(\\w)+(.(\\d)+)+)", 
                              dlink = "(DCS-(\\d)+\\w)", tplink = "TP-Link IP-Camera", 
                              canon = "Canon Network Camera", vivotek = "Vivotek Network Camera", 
                              sony = "((SONY|Sony).Network Camera.(\\w)+-(\\w)+)")
  
  if (shodan_query == shodan_search_list[1]) {
    software_info <- parseAxisCamera(software_info, regex_camera_search["axis"])
  } else if (shodan_query == shodan_search_list[2]) {
    software_info <- parseDlinkCamera(software_info, regex_camera_search["dlink"])
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
    software_info <- parseSonyCamera(software_info, regex_camera_search["sony"])
  }
  
  software_info
}

#' Search cameras with Shodan
#' 
#' @param shodan_query, query used for searching information

searchCamerasWithShodan <- function(shodan_query) {
  result_to_return <- NULL
  result <- shodan_search(query = shodan_query)
  
  if (result$total > 100) {
    result_to_return = rbind(result_to_return, data.frame(country_code = result$matches$location$country_code, 
                                                          country_name = result$matches$location$country_name, 
                                                          latitude = result$matches$location$latitude, 
                                                          longitude = result$matches$location$longitude, 
                                                          ip_str = result$matches$ip_str, 
                                                          data = result$matches$data, 
                                                          vendor = NA, 
                                                          model = NA, 
                                                          version = 0, 
                                                          stringsAsFactors = FALSE))

    for (i in 2:round(result$total/100)) {
      result <- shodan_search(query = shodan_query, page = i)
      
      result_to_return = rbind(result_to_return, data.frame(country_code = result$matches$location$country_code, 
                                                            country_name = result$matches$location$country_name, 
                                                            latitude = result$matches$location$latitude, 
                                                            longitude = result$matches$location$longitude, 
                                                            ip_str = result$matches$ip_str, 
                                                            data = result$matches$data, 
                                                            vendor = NA, 
                                                            model = NA, 
                                                            version = 0, 
                                                            stringsAsFactors = FALSE))
      Sys.sleep(0.5)
    }
  } else {
    result_to_return <- data.frame(country_code = result$matches$location$country_code, 
                                   country_name = result$matches$location$country_name, 
                                   latitude = result$matches$location$latitude, 
                                   longitude = result$matches$location$longitude, 
                                   ip_str = result$matches$ip_str, 
                                   data = result$matches$data, 
                                   vendor = NA, 
                                   model = NA, 
                                   version = 0, 
                                   stringsAsFactors = FALSE)
  }
  
  getCameraSoftware(result_to_return, shodan_query)
}

#' Get list of worldwide cameras

getWorldWideCameras <- function(){
  shodan_search_list <- c("axis camera", "d-link dcs", "tp-link ip-camera", 
                          "canon network camera", "vivotek camera", "sony camera")
  
  shodan_cameras_data <- NULL
  for (i in 1:length(shodan_search_list)) {
    shodan_cameras_data = rbind(shodan_cameras_data, searchCamerasWithShodan(shodan_search_list[i]))
  }
  
  ##Drop rows that have NA values
  shodan_cameras_data <- shodan_cameras_data %>% drop_na()
  
  shodan_cameras_data
}

#' Join Shodan results with CVEs information
#' 
#' @param shodan_cameras_data, data frame with Shodan results
#' @param cve_cameras_data, data frame with CVEs information
#' 
#' @return schodan_cves_join, data frame with joined information 

leftJoinShodanWithCVEsInfo <- function(shodan_cameras_data, cve_cameras_data){
  ##Join shodan search result with cameras CVEs information
  shodan_cves_join <- left_join(shodan_cameras_data, cve_cameras_data)
  
  shodan_cves_join
}

#' Remove Na values
#' 
#' @param df, data frame with Na values
#' 
#' @return df, data frame without Na values

getJoinedInfoWithNoNa <- function(df){
  df <- df %>% drop_na()
  df
}

#' Create factor for Shodan results
#' 
#' @param df, data frame with Shodan results
#' 
#' @return df, data frame with factors for model, vendor, country_name and country_code

createFactorsForShodanData <- function(df){
  df <- transform(df, model = factor(model))
  df <- transform(df, vendor = factor(vendor))
  df <- transform(df, country_name = factor(country_name))
  df <- transform(df, country_code = factor(country_code))
  df
}

#' Create factor for CVE dataframe
#'
#' @param db, data frame with CVEs
#' 
#' @df, data frame with factors for vendor and model

createFactorsForCVEData <- function(df){
  ##Factors
  df <- transform(df, vendor = factor(vendor))
  df <- transform(df, model = factor(model))
  
  df
}

#' Get percentage of AXIS 2100 Network cameras
#' 
#' @param shodan_cves_join, joined information of shodan and CVEs data
#' 
#' @return axis.percent, percentage of AXIS 2100 Network Cameras
#' 

calculatePercentOfAxis2100NC <- function(shodan_cves_join) {
  shodan_cves_join.no_na <- shodan_cves_join %>% drop_na()
  
  ## Get percent of 2100 network camera by country
  axis.total <-  data.frame(table(shodan_cves_join.no_na$country_code))
  colnames(axis.total) <- c("country", "freq1")
  
  axis.2100 <- data.frame(table(shodan_cves_join.no_na[shodan_cves_join.no_na$model == "2100 network camera",]$country_code))
  colnames(axis.2100) <- c("country", "freq2")
  
  axis.percent <- left_join(axis.total, axis.2100)
  axis.percent$percent <- (axis.percent$freq2/axis.percent$freq1)*100
  axis.percent <- axis.percent %>% drop_na()
  
  axis.percent
}
