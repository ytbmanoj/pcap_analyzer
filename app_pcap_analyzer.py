from pcapAnalyser import analyzeFile


def list_asset(pcap_file_name):
    
    file_location = f"./app/uploads/{pcap_file_name}"  
    target=analyzeFile(file_location)
    
    print(target)
    return target

if __name__ == "__main__":
    print(list_asset("PCAPdroid_09_Apr_22_18_59.pcap"))