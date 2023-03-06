# conn_processing.py

# Creator: Miguel Ivars Carbo - University of Zaragoza
# Date: 06/03/2023

# This Script will allow the user to label the logs from the CIC-IDS Dataset.
# The labeling is made according to the instructions provided in the CIC-IDS Dataset
# information. It's puropose is to append the 'MALIGN' or 'BENIGN' data at the
# end of a tsv log.

import csv
from datetime import datetime, timedelta

# Open input and output files
with open('E:\Logs_Zeek\CIC-IDS\Friday-WorkingHours\conn.tsv', 'r') as in_file, open('E:\Logs_Zeek\CIC-IDS\Friday-WorkingHours\conn_label.tsv', 'w', newline='') as out_file:
    
    # Day of the log
    logday = str(input("Introduce the day of your log - tuesday / wednesday / thursday / friday - are accepted: "))
    while (str(logday.upper()) != ('TUESDAY') and str(logday.upper()) != ('WEDNESDAY') and str(logday.upper()) != ('THURSDAY') and str(logday.upper()) != ('FRIDAY') ):
        logday = str(input("Please, introduce the day as explained previously: "))
    
    # Create a tab-separated value reader and writer
    tsv_reader = csv.reader(in_file, delimiter='\t')
    tsv_writer = csv.writer(out_file, delimiter='\t')

    # Read and skip over the metadata lines
    line = next(tsv_reader)
    
    # En caso de comentarios
    while line[0].startswith('#'):
        line = next(tsv_reader)
    
    # Line Counter
    i = 0

    if logday.upper() == 'TUESDAY':
        
        # Attack Timestamps
        nueve_y_veinte = datetime.strptime("09:20:00", "%H:%M:%S")
        diez_y_veinte = datetime.strptime("10:20:00", "%H:%M:%S")
        dos_en_punto = datetime.strptime("14:00:00", "%H:%M:%S")
        tres_en_punto = datetime.strptime("15:00:00", "%H:%M:%S")
        
        # Attack Implicated IPs
        ip_origen = '172.16.0.1'
        ip_destino = '192.168.10.50'
        
        line_timestamp = datetime.strptime("00:00:00","%H:%M:%S")
        
        # Procesado de cada linea
        for line in tsv_reader:
            
            if len(line) > 4:
                
                # Extraccion de la Hora
                line_timestamp_str = line[0]
                line_day, line_time_str = line_timestamp_str.split(' ')
                
                # Formato timestamp de Python - permite comparar Horas
                line_timestamp = datetime.strptime(line_time_str,"%H:%M:%S") - timedelta(hours=3)
                
                # Attacks performed on wednesday
                ftp_patator = (line_timestamp >= nueve_y_veinte) and (line_timestamp <= diez_y_veinte) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '21' or line[4] == '80')
                ssh_patator = (line_timestamp >= dos_en_punto) and (line_timestamp <= tres_en_punto) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '22')
                
                # Attack detection
                if  (ftp_patator or ssh_patator): 
                    label = 'MALIGN'
                else:
                    label = 'BENIGN'
                
                # Add the 'Label' field to the line
                line.append(label)

                # Write the line to the output file
                tsv_writer.writerow(line)
                
                i+=1
    
    elif logday.upper() == 'WEDNESDAY':
        
        # Attack Timestamps
        once_y_diez = datetime.strptime("11:10:00", "%H:%M:%S")
        once_y_veintitres = datetime.strptime("11:23:00", "%H:%M:%S")
        diez_cuarenta_y_tres = datetime.strptime("10:43:00", "%H:%M:%S")
        once_en_punto = datetime.strptime("11:00:00", "%H:%M:%S")
        diez_catorce = datetime.strptime("10:14:00", "%H:%M:%S")
        diez_y_treintaicinco = datetime.strptime("10:35:00", "%H:%M:%S")
        nueve_y_cuarentaysiete = datetime.strptime("09:47:00", "%H:%M:%S")
        diez_y_diez = datetime.strptime("10:10:00", "%H:%M:%S")
        quince_y_doce = datetime.strptime("15:12:00", "%H:%M:%S")
        quince_y_treintaydos = datetime.strptime("15:32:00", "%H:%M:%S")
        
        # Attack implicated IPs        
        ip_origen = '172.16.0.1'
        ip_destino = '192.168.10.50'
        ip_destino_2 = '192.168.10.51'
        
        line_timestamp = datetime.strptime("00:00:00","%H:%M:%S")

        # Procesado de cada linea
        for line in tsv_reader:
            
            if len(line) > 4:
                
                # Extraccion de la Hora
                line_timestamp_str = line[0]
                line_day, line_time_str = line_timestamp_str.split(' ')
                
                # Formato timestamp de Python - permite comparar Horas
                line_timestamp = datetime.strptime(line_time_str,"%H:%M:%S") - timedelta(hours=3)
                
                # Attacks performed on Wednesday
                dos_goldeneye = (line_timestamp >= once_y_diez) and (line_timestamp <= once_y_veintitres) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '80')
                dos_hulk = (line_timestamp >= diez_cuarenta_y_tres) and (line_timestamp <= once_en_punto) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '80')
                dos_slowhttp = (line_timestamp >= diez_catorce) and (line_timestamp <= diez_y_treintaicinco) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '80')
                dos_slowloris = (line_timestamp >= nueve_y_cuarentaysiete) and (line_timestamp <= diez_y_diez) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '80')
                heartbleed = (line_timestamp >= quince_y_doce) and (line_timestamp <= quince_y_treintaydos) and (line[1] == ip_origen) and (line[3] == ip_destino_2) and (line[4] == '443')
                
                # Attack detection
                if  (dos_goldeneye or dos_hulk or dos_slowhttp or dos_slowloris or heartbleed): 
                    label = 'MALIGN'
                else:
                    label = 'BENIGN'
                
                # Add the 'Label' field to the line
                line.append(label)

                # Write the line to the output file
                tsv_writer.writerow(line)
                
                i+=1
    
    elif logday.upper() == 'THURSDAY':
        
        # Attack Timestamps
        dos_y_diecynueve = datetime.strptime("14:19:00", "%H:%M:%S")
        dos_y_veintiuno = datetime.strptime("14:21:00", "%H:%M:%S")
        dos_y_treintaytres = datetime.strptime("14:33:00", "%H:%M:%S")
        dos_y_treintaycinco = datetime.strptime("14:35:00", "%H:%M:%S")
        diez_cuarenta = datetime.strptime("10:40:00", "%H:%M:%S")
        diez_cuarenta_ydos = datetime.strptime("10:42:00", "%H:%M:%S")
        nueve_y_veinte = datetime.strptime("09:20:00", "%H:%M:%S")
        diez_en_punto = datetime.strptime("10:00:00", "%H:%M:%S")
        diez_y_quince = datetime.strptime("10:15:00", "%H:%M:%S")
        diez_y_treintaycinco = datetime.strptime("10:35:00", "%H:%M:%S")
        
        # Attack implicated IPs
        ip_origen_i = '192.168.10.8'
        ip_destino_i = '205.174.168.73'
        ip_origen = '172.16.0.1'
        ip_destino = '192.168.10.50'
        
        line_timestamp = datetime.strptime("00:00:00","%H:%M:%S") 

        # Procesado de cada linea
        for line in tsv_reader:
            
            if len(line) > 4:
                
                # Extraccion de la Hora
                line_timestamp_str = line[0]
                line_day, line_time_str = line_timestamp_str.split(' ')
                
                # Formato timestamp de Python - permite comparar Horas
                line_timestamp = datetime.strptime(line_time_str,"%H:%M:%S") - timedelta(hours=3)
                
                # Attacks performed on Wednesday
                infiltration = ((line_timestamp >= dos_y_diecynueve and line_timestamp <= dos_y_veintiuno) or (line_timestamp >= dos_y_treintaytres and line_timestamp <= dos_y_treintaycinco)) and (line[1] == ip_origen_i) and (line[3] == ip_destino_i) and (line[4] == '444')
                sql_injection = (line_timestamp >= diez_en_punto) and (line_timestamp <= diez_cuarenta_ydos) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '80')
                brute_force = (line_timestamp >= nueve_y_veinte) and (line_timestamp <= diez_en_punto) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '80')
                xss = (line_timestamp >= diez_y_quince) and (line_timestamp <= diez_y_treintaycinco) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '80')
                
                # Attack detection
                if  (infiltration or sql_injection or brute_force or xss): 
                    label = 'MALIGN'
                else:
                    label = 'BENIGN'
                
                # Add the 'Label' field to the line
                line.append(label)

                # Write the line to the output file
                tsv_writer.writerow(line)
                
                i+=1
    
    elif logday.upper() == 'FRIDAY':
 
        # Attack Timestamps       
        tres_y_cincuentayseis = datetime.strptime("15:56:00", "%H:%M:%S")
        cuatro_y_diecyseis = datetime.strptime("16:16:00", "%H:%M:%S")
        una_y_cincuentaycinco = datetime.strptime("13:55:00", "%H:%M:%S")
        tres_y_veintinueve = datetime.strptime("15:29:00", "%H:%M:%S")
        
        # Attack implicated IPs
        ip_origen = '172.16.0.1'
        ip_destino = '192.168.10.50'
        
        line_timestamp = datetime.strptime("00:00:00","%H:%M:%S")
        
        # Procesado de cada linea
        for line in tsv_reader:
            
            if len(line) > 4:
                
                # Extraccion de la Hora
                line_timestamp_str = line[0]
                line_day, line_time_str = line_timestamp_str.split(' ')
                
                # Formato timestamp de Python - permite comparar Horas
                line_timestamp = datetime.strptime(line_time_str,"%H:%M:%S") - timedelta(hours=3)
                
                # Attacks performed on wednesday
                ddos = (line_timestamp >= tres_y_cincuentayseis) and (line_timestamp <= cuatro_y_diecyseis) and (line[1] == ip_origen) and (line[3] == ip_destino) and (line[4] == '21' or line[4] == '80')
                port_scan = (line_timestamp >= una_y_cincuentaycinco) and (line_timestamp <= tres_y_veintinueve) and (line[1] == ip_origen) and (line[3] == ip_destino)
                
                # Attack detection
                if  (ddos or port_scan): 
                    label = 'MALIGN'
                else:
                    label = 'BENIGN'
                
                # Add the 'Label' field to the line
                line.append(label)

                # Write the line to the output file
                tsv_writer.writerow(line)
                
                i+=1
    
    else:
        print('Something went wrong with your day selection')
    
    print('Total lines labeled = '+str(i))
    print('Finishing Execution')
