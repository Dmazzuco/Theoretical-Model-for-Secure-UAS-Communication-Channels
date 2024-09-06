

# Imports
import random
import pandas as pd
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Constants

HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
NO = 0

LOW_ATTENUATION = 0.80
MEDIUM_ATTENUATION = 0.60
HIGH_ATTENUATION = 0.30
VERY_HIGH_ATTENUATION = 0.15

INITIAL_LIKELIHOOD = 0.75   # It is more likely that the attack happen in the CONOPs.

INCREMENTED = 1
INCREASED = 2
AUGMENTED = 3


NUMBER_OF_SIMULATIONS = 1000000 # Change to the appropriate number of simulations
####################################################
####################################################
####################################################
# Model inputs
# Protocols (TLS, MLS, PSK)
# Attenuation (Over the land) - If necessary add more environments
# Frequency (HF, VHF, UHF)

# 9 Simulation combining all possible variations of the inputs 


# Model outputs

# Sim 1:
# tls_hf_land_jam_result
# tls_hf_land_high_result

# Sim 2:
# tls_vhf_land_jam_result
# tls_vhf_land_high_result

# Sim 3:
# tls_uhf_land_jam_result
# tls_uhf_land_high_result

# Sim 4:
# mls_hf_land_jam_result
# mls_hf_land_high_result

# Sim 5:
# mls_vhf_land_jam_result
# mls_vhf_land_high_result

# Sim 6:
# mls_uhf_land_jam_result
# mls_uhf_land_high_result

# Sim 7:
# psk_hf_land_jam_result
# psk_hf_land_high_result

# Sim 8:
# psk_vhf_land_jam_result
# psk_vhf_land_high_result

# Sim 9:
# psk_uhf_land_jam_result
# psk_uhf_land_high_result


####################################################
####################################################
####################################################

# Protocols - dictionary of vulnerabilities

# TLS - Transport Layer (Layer 4)
# Jamming Vulnerability = "High"
# Highjacking Vulnerability = "Medium"
# RF Footprint = "High"
# Persistence = "Medium"    - Detectability (rounds to estabilhish a connection)

# MLS - Application Layer (Layer 5)
# Jamming Vulnerability = "Low"
# Highjacking Vulnerability = "Low"
# RF Footprint = "Medium"
# Persistence = "Low"       - Detectability (rounds to estabilhish a connection)

# PSK - Link Layer (Layer 2)
# Jamming Vulnerability = "Low"
# Highjacking Vulnerability = "High"
# RF Footprint = "Low"
# Persistence = "Low"       - Detectability (rounds to estabilhish a connection)


protocols = {
    "TLS": {
        "Jamming Vulnerability": HIGH,
        "Highjacking Vulnerability": MEDIUM,
        "RF Footprint": HIGH,
        "Persistence": MEDIUM
    },
    "MLS": {
        "Jamming Vulnerability": LOW,
        "Highjacking Vulnerability": LOW,
        "RF Footprint": MEDIUM,
        "Persistence": LOW
    },
    "PSK": {
        "Jamming Vulnerability": LOW,
        "Highjacking Vulnerability": HIGH,
        "RF Footprint": LOW,
        "Persistence": LOW
    }
}

####################################################
####################################################
####################################################

# Frequencies - dictionary of frequencies - Physical Layer (Layer 1)
# HF
# Attenuation = "High"
# Operating Range = "High"

# VHF
# Attenuation = "Medium"
# Operating Range = "Medium"

# UHF
# Attenuation = "Low"
# Operating Range = "Low"

# To simplify the model, the operating range is out of scope


frequencies = {
    "HF": {
        "Attenuation": HIGH
    },
    "VHF": {
        "Attenuation": MEDIUM
    },
    "UHF": {
        "Attenuation": LOW
    }
}

####################################################
####################################################
####################################################

# Environments - dictionary of environments
# Over the ice (land) = "Medium"
# Add more environments if necessary
# Adjust the attenuation factor if necessary


environments = {
    "Over the ice (land)": MEDIUM
}

####################################################
####################################################
####################################################

# Attenuation - Function on layer 1
'''
Attenuation affects the operating range of the communication system.
Inputs: frequency and environment
Outputs: attenuation factor
'''

def attenuation(frequency, environ):
    # attenuation score - inicialized as zero
    attenuation_score = NO
    # What is the environment?
    # if it is over the ice (land) then the attenuation is medium

    if environ == "Over the ice (land)":
        # INCREASED = 2
        attenuation_score = attenuation_score + INCREASED
   
    # What is the frequency?
    # if it is HF then the attenuation is high
    # else if it is VHF then the attenuation is medium
    # else if it is UHF then the attenuation is low
    if frequency == "HF":
        # AUGMENTED = 3
        attenuation_score = attenuation_score + AUGMENTED

    elif frequency == "VHF":
        # INCREASED = 2
        attenuation_score = attenuation_score + INCREASED

    else:
        # INCREMENTED = 1
        attenuation_score = attenuation_score + INCREMENTED

    # attenuation score will vary from 3 to 6
    # The attenuation factor is a number between 0 and 1
    # 3 is a low attenuation  
    # 4 is a medium attenuation
    # 5 is a high attenuation
    # 6 is a very high attenuation
    # The attenuation factor is calculated as follows:
    # 3 -> 0.80
    # 4 -> 0.60
    # 5 -> 0.30
    # 6 -> 0.15
    if attenuation_score == 3:
        return LOW_ATTENUATION
    elif attenuation_score == 4:
        return MEDIUM_ATTENUATION
    elif attenuation_score == 5:
        return HIGH_ATTENUATION
    else:
        return VERY_HIGH_ATTENUATION

    
####################################################
####################################################
####################################################

# The attenuation factor will affect:
# the operating range of the communication system (Out of scope)
# the likelihood of the attack happen - The attcker must be closer to the communication system   


# Does the attack happen?
# Initial likelihood is 75-25 - It is more likely that the attack happen in the CONOPs.
# The likelihood of the attack happen is calculated as follows:
# Likelihood of the attack happen (0.75) * attenuation factor + persistence

def is_attack_happen(attenuation_factor, protocol):
    # Calcula a likelihood
    persistence = protocols[protocol]["Persistence"]
    if persistence == HIGH:
        persistence_score = 0.3

    elif persistence == MEDIUM:
        persistence_score = 0.2

    else:
        persistence_score = 0.1

    att = 1 - attenuation_factor
    likelihood = (INITIAL_LIKELIHOOD * att) + persistence_score
    #print(f"Likelihood: {likelihood}")

    result = random.random()
    #print(f"Result: {result}")
    return result < likelihood


####################################################
####################################################
####################################################

# Jammer - Function
'''
Inputs: protocol, frequency
Outputs: jammer status (success or fail)
'''
def jammer(protocol):

    # What is the protocol? - RF Footprint, Jamming Vulnerability and Persistence
    # Check the protocol and get the RF Footprint, Jamming Vulnerability and Persistence

    # If it is TLS the RF Footprint is high, the Jamming Vulnerability is high and the Persistence is medium
    if protocol == "TLS":
        rf_footprint = HIGH
        jamming_vulnerability = HIGH
        persistence = MEDIUM

    # else if it is MLS the RF Footprint is medium, the Jamming Vulnerability is low and the Persistence is low
    elif protocol == "MLS":
        rf_footprint = MEDIUM
        jamming_vulnerability = LOW
        persistence = LOW

    # else if it is PSK the RF Footprint is low, the Jamming Vulnerability is low and the Persistence is high
    else:
        rf_footprint = LOW
        jamming_vulnerability = LOW
        persistence = LOW

   
    # What is the RF Footprint?
    # if it is high then the likelihood of the attack happen is high
    if rf_footprint == HIGH:
        success_rate = 3

    elif rf_footprint == MEDIUM:
        success_rate = 2

    else:
        success_rate = 1

    #print(f"Success rate: {success_rate}")

    
    # What is the Jamming Vulnerability?
    if jamming_vulnerability == HIGH:
        success_rate = success_rate + 3

    elif jamming_vulnerability == MEDIUM:
        success_rate = success_rate + 2

    else:
        success_rate = success_rate + 1

    # What is the Persistence?
    if persistence == HIGH:
        success_rate = success_rate + 3

    elif persistence == MEDIUM:
        success_rate = success_rate + 2

    else:
        success_rate = success_rate + 1

    # parameters are between 3 and 9
    success_rate = success_rate / 9 # success_rate varies from 0.33 to 1.0
    #print(f"Success rate: {success_rate}")
    success_likelihood = random.random() < success_rate
    #print(f"Success likelihood: {success_likelihood}")
    return success_likelihood


####################################################
####################################################
####################################################


# Highjacker - Function
'''
Inputs: protocol
Outputs: highjacker status (success or fail)
'''

def highjacker(protocol):
    # What is the protocol? - Highjacking Vulnerability and Persistence
    # Check the protocol and get the Highjacking Vulnerability and Persistence
    # If it is TLS the Highjacking Vulnerability is medium and the Persistence is medium
    if protocol == "TLS":
        highjacking_vulnerability = MEDIUM
        persistence = MEDIUM

    # else if it is MLS the Highjacking Vulnerability is low and the Persistence is low
    elif protocol == "MLS":
        highjacking_vulnerability = LOW
        persistence = LOW

    # else if it is PSK the Highjacking Vulnerability is high and the Persistence is high
    else:
        highjacking_vulnerability = HIGH
        persistence = LOW

    # What is the Highjacking Vulnerability?
    # if it is high then the likelihood of the attack happen is high
    if highjacking_vulnerability == HIGH:
        success_rate = 3

    elif highjacking_vulnerability == MEDIUM:
        success_rate = 2

    else:
        success_rate = 1


    # What is the percistence?
    if persistence == HIGH:
        success_rate = success_rate + 3

    elif persistence == MEDIUM:
        success_rate = success_rate + 2

    else:
        success_rate = success_rate + 1

    # parameters are between 3 and 6
    success_rate = success_rate / 6 # success_rate varies from 0.5 to 1.0
    #print(f"Success rate: {success_rate}")
    success_likelihood = random.random() < success_rate
    #print(f"Success likelihood: {success_likelihood}")

    return success_likelihood


####################################################
####################################################
####################################################
####################################################
####################################################
####################################################

print ("\n\nBegining Simulation\n")

####################################################
####################################################
####################################################
####################################################
# TLS
####################################################
####################################################
####################################################

####################################################
# 1st Simulation: Over the ice (land), TLS, HF #####
####################################################

# Simulation - Over the ice (land), TLS, HF

#print ("CONOPS: Over the ice (land)\n")

print ("1st simulation: TLS, HF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with TLS
protocol = "TLS"

# Choose the frequency
# Start with HF
frequency = "HF"


# Lists to store the results
tls_hf_land_jam_result = []
tls_hf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - TLS, HF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list tls_hf_land_result
            tls_hf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list tls_hf_land_result
            tls_hf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list ipsec_hf_land_result
        tls_hf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list tls_hf_land_result
            tls_hf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list tls_hf_land_result
            tls_hf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list tls_hf_land_result
        tls_hf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", tls_hf_land_jam_result)
#print ("\nHighjacker: ", tls_hf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_1 = tls_hf_land_jam_result.count("Success")
num_success_high_1 = tls_hf_land_high_result.count("Success")
final_result_jam_1 = num_success_jam_1 / NUMBER_OF_SIMULATIONS
final_result_high_1 = num_success_high_1 / NUMBER_OF_SIMULATIONS
# print avarege of the results - Jammer and Highjacker

print ('\nJammer (TLS, Land, HF): ', final_result_jam_1)
print ('\nHighjacker (TLS, Land, HF): ', final_result_high_1)

####################################################
####################################################
####################################################

####################################################
# 2nd Simulation: Over the ice (land), TLS, VHF ####
####################################################

# Simulation

print ("\n\n2nd simulation: TLS, VHF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with TLS
protocol = "TLS"

# Choose the frequency
# Start with VHF
frequency = "VHF"

# List to store the results
tls_vhf_land_jam_result = []
tls_vhf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - TLS, VHF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list tls_vhf_land_result
            tls_vhf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list tls_vhf_land_result
            tls_vhf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list tls_vhf_land_result
        tls_vhf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list tls_vhf_land_result
            tls_vhf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list tls_vhf_land_result
            tls_vhf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list tls_vhf_land_result
        tls_vhf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", tls_vhf_land_jam_result)
#print ("\nHighjacker: ", tls_vhf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_2 = tls_vhf_land_jam_result.count("Success")
num_success_high_2 = tls_vhf_land_high_result.count("Success")
final_result_jam_2 = num_success_jam_2 / NUMBER_OF_SIMULATIONS
final_result_high_2 = num_success_high_2 / NUMBER_OF_SIMULATIONS
# print avantge of the results - Jammer and Highjacker

print ('\nJammer (TLS, Land, VHF): ', final_result_jam_2)
print ('\nHighjacker (TLS, Land, VHF): ', final_result_high_2)

####################################################
####################################################
####################################################

####################################################
# 3rd Simulation: Over the ice (land), TLS, UHF ####
####################################################


# Simulation

print("\n\n3rd simulation: TLS, UHF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with TLS
protocol = "TLS"

# Choose the frequency
# Start with UHF
frequency = "UHF"


# Lists to store the results
tls_uhf_land_jam_result = []
tls_uhf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - TLS, UHF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list tls_uhf_land_result
            tls_uhf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list tls_uhf_land_result
            tls_uhf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list tls_uhf_land_result
        tls_uhf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list tls_uhf_land_result
            tls_uhf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list tls_uhf_land_result
            tls_uhf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list tls_uhf_land_result
        tls_vhf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", tls_uhf_land_jam_result)
#print ("\nHighjacker: ", tls_uhf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_3 = tls_uhf_land_jam_result.count("Success")
num_success_high_3 = tls_uhf_land_high_result.count("Success")
final_result_jam_3 = num_success_jam_3 / NUMBER_OF_SIMULATIONS
final_result_high_3 = num_success_high_3 / NUMBER_OF_SIMULATIONS
# print avantge of the results - Jammer and Highjacker
print ('\nJammer (TLS, Land, UHF): ', final_result_jam_3)
print ('\nHighjacker (TLS, Land, UHF): ', final_result_high_3)


####################################################
####################################################
####################################################
####################################################
# MLS
####################################################
####################################################
####################################################


####################################################
# 4th Simulation: Over the ice (land), MLS, HF ###
####################################################

# Simulation - Over the ice (land), MLS, HF
#print ("\n\nFirst CONOPS: Over the ice (land)\n")

print("\n4th simulation: MLS, HF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with MLS
protocol = "MLS"

# Choose the frequency
# Start with HF
frequency = "HF"


# Lists to store the results
mls_hf_land_jam_result = []
mls_hf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - MLS, HF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list mls_hf_land_result
            mls_hf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list mls_hf_land_result
            mls_hf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list mls_hf_land_result
        mls_hf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list mls_hf_land_result
            mls_hf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list mls_hf_land_result
            mls_hf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list mls_hf_land_result
        mls_hf_land_high_result.append("Fail")
        

#print ("\nResults: \n")
#print ("\nJammer: ", mls_hf_land_jam_result)
#print ("\nHighjacker: ", mls_hf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_4 = mls_hf_land_jam_result.count("Success")
num_success_high_4 = mls_hf_land_high_result.count("Success")
final_result_jam_4 = num_success_jam_4 / NUMBER_OF_SIMULATIONS
final_result_high_4 = num_success_high_4 / NUMBER_OF_SIMULATIONS
# print avarege of the results - Jammer and Highjacker

print ('\nJammer (MLS, Land, HF): ', final_result_jam_4)
print ('\nHighjacker (MLS, Land, HF): ', final_result_high_4)

####################################################
####################################################
####################################################

####################################################
# 5th Simulation: Over the ice (land), MLS, VHF ##
####################################################

# Simulation

print("\n5th simulation: MLS, VHF\n")
# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with MLS
protocol = "MLS"

# Choose the frequency
# Start with VHF
frequency = "VHF"


# Lists to store the results
mls_vhf_land_jam_result = []
mls_vhf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - MLS, VHF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list mls_vhf_land_result
            mls_vhf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list mls_vhf_land_result
            mls_vhf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list mls_vhf_land_result
        mls_vhf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list mls_vhf_land_result
            mls_vhf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list mls_vhf_land_result
            mls_vhf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list mls_vhf_land_result
        mls_vhf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", mls_vhf_land_jam_result)
#print ("\nHighjacker: ", mls_vhf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_5 = mls_vhf_land_jam_result.count("Success")
num_success_high_5 = mls_vhf_land_high_result.count("Success")
final_result_jam_5 = num_success_jam_5 / NUMBER_OF_SIMULATIONS
final_result_high_5 = num_success_high_5 / NUMBER_OF_SIMULATIONS
# print avarege of the results - Jammer and Highjacker

print ('\nJammer (MLS, Land, VHF): ', final_result_jam_5)
print ('\nHighjacker (MLS, Land, VHF): ', final_result_high_5)

####################################################
####################################################
####################################################

####################################################
# 6th Simulation: Over the ice (land), MLS, UHF #
####################################################

# Simulation

print("\n\n6th simulation: MLS, UHF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with MLS
protocol = "MLS"

# Choose the frequency
# Start with UHF
frequency = "UHF"


# Lists to store the results
mls_uhf_land_jam_result = []
mls_uhf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - MLS, UHF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list mls_uhf_land_result
            mls_uhf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list mls_uhf_land_result
            mls_uhf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list mls_uhf_land_result
        mls_uhf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list mls_uhf_land_result
            mls_uhf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list mls_uhf_land_result
            mls_uhf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list mls_uhf_land_result
        mls_vhf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", mls_uhf_land_jam_result)
#print ("\nHighjacker: ", mls_uhf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_6 = mls_uhf_land_jam_result.count("Success")
num_success_high_6 = mls_uhf_land_high_result.count("Success")
final_result_jam_6 = num_success_jam_6 / NUMBER_OF_SIMULATIONS
final_result_high_6 = num_success_high_6 / NUMBER_OF_SIMULATIONS
# print avantge of the results - Jammer and Highjacker
print ('\nJammer (MLS, Land, UHF): ', final_result_jam_6)
print ('\nHighjacker (MLS, Land, UHF): ', final_result_high_6)


####################################################
####################################################
####################################################
####################################################
# PSK
####################################################
####################################################
####################################################

####################################################
# 7th Simulation: Over the ice (land), PSK, HF ####
####################################################

# Simulation - Over the ice (land), PSK, HF

#print ("\n\nCONOPS: Over the ice (land)\n")

print ("\n7th simulation: Over the ice (land), PSK, HF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with PSK
protocol = "PSK"

# Choose the frequency
# Start with HF
frequency = "HF"


# Lists to store the results
psk_hf_land_jam_result = []
psk_hf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - PSK, HF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list psk_hf_land_result
            psk_hf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list psk_hf_land_result
            psk_hf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list psk_hf_land_result
        psk_hf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list psk_hf_land_result
            psk_hf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list psk_hf_land_result
            psk_hf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list psk_hf_land_result
        psk_hf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", psk_hf_land_jam_result)
#print ("\nHighjacker: ", psk_hf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_7 = psk_hf_land_jam_result.count("Success")
num_success_high_7 = psk_hf_land_high_result.count("Success")
final_result_jam_7 = num_success_jam_7 / NUMBER_OF_SIMULATIONS
final_result_high_7 = num_success_high_7 / NUMBER_OF_SIMULATIONS
# print avarege of the results - Jammer and Highjacker

print ('\nJammer (PSK, Land, HF): ', final_result_jam_7)
print ('\nHighjacker (PSK, Land, HF): ', final_result_high_7)

####################################################
####################################################
####################################################

####################################################
# 8th Simulation: Over the ice (land), PSK, VHF ####
####################################################

# Simulation

print ("\n\n8th simulation: PSK, VHF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with PSK
protocol = "PSK"

# Choose the frequency
# Start with VHF
frequency = "VHF"

# List to store the results
psk_vhf_land_jam_result = []
psk_vhf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - PSK, VHF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list psk_vhf_land_result
            psk_vhf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list psk_vhf_land_result
            psk_vhf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list psk_vhf_land_result
        psk_vhf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list psk_vhf_land_result
            psk_vhf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list psk_vhf_land_result
            psk_vhf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list psk_vhf_land_result
        psk_vhf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", psk_vhf_land_jam_result)
#print ("\nHighjacker: ", psk_vhf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_8 = psk_vhf_land_jam_result.count("Success")
num_success_high_8 = psk_vhf_land_high_result.count("Success")
final_result_jam_8 = num_success_jam_8 / NUMBER_OF_SIMULATIONS
final_result_high_8 = num_success_high_8 / NUMBER_OF_SIMULATIONS
# print avantge of the results - Jammer and Highjacker

print ('\nJammer (PSK, Land, VHF): ', final_result_jam_8)
print ('\nHighjacker (PSK, Land, VHF): ', final_result_high_8)

####################################################
####################################################
####################################################

####################################################
# 9th Simulation: Over the ice (land), PSK, UHF ####
####################################################

# Simulation

print("\n\n9th simulation: PSK, UHF\n")

# The Operator will choose the protocol, the frequency and the environment (CONOPS)

# Choose the environment
# Start with Over the ice (land)
environment = "Over the ice (land)"

# Choose the protocol
# Start with PSK
protocol = "PSK"

# Choose the frequency
# Start with UHF
frequency = "UHF"


# Lists to store the results
psk_uhf_land_jam_result = []
psk_uhf_land_high_result = []

# Simulation loop
for attack in range(1, NUMBER_OF_SIMULATIONS + 1):
    # Calculate the attenuation factor
    # call the function attenuation
    attenuation_factor = attenuation(frequency, environment)
    #print(f"Attenuation factor: {attenuation_factor}")

    # Calculate the likelihood of the attack happen
    # Call the function is_attack_happen
    attack_happen = is_attack_happen(attenuation_factor, protocol)
    #print(f"Attack happen: {attack_happen}")

    # Result goes to list - PSK, UHF, Over the ice (land)

    if attack_happen:
        # call the function jammer
        jam = jammer(protocol)
        
        # Check if the Jammer was successful
        if jam:
            # append the result "Success" to the list psk_uhf_land_result
            psk_uhf_land_jam_result.append("Success")

        else:
            # append the result "Fail" to the list psk_uhf_land_result
            psk_uhf_land_jam_result.append("Fail")
    
    else:
        # append the result "Fail" to the list psk_uhf_land_result
        psk_uhf_land_jam_result.append("Fail") 

    ####################################################

    # if attackhappen call now the function highjacker
    
    if attack_happen:
        highjack = highjacker(protocol)
        
        # Check if the Highjacker was successful
        if highjack:
            # append the result "Success" to the list psk_uhf_land_result
            psk_uhf_land_high_result.append("Success")

        else:
            # append the result "Fail" to the list psk_uhf_land_result
            psk_uhf_land_jam_result.append("Fail")

    else:
        # append the result "Fail" to the list psk_uhf_land_result
        psk_vhf_land_high_result.append("Fail")

#print ("\nResults: \n")
#print ("\nJammer: ", tls_uhf_land_jam_result)
#print ("\nHighjacker: ", tls_uhf_land_high_result)
print ("\nResults recorded\n")

# Avarege of the results - Number of Success / Number of Simulations
num_success_jam_9 = psk_uhf_land_jam_result.count("Success")
num_success_high_9 = psk_uhf_land_high_result.count("Success")
final_result_jam_9 = num_success_jam_9 / NUMBER_OF_SIMULATIONS
final_result_high_9 = num_success_high_9 / NUMBER_OF_SIMULATIONS
# print avantge of the results - Jammer and Highjacker
print ('\nJammer (PSK, Land, UHF): ', final_result_jam_9)
print ('\nHighjacker (PSK, Land, UHF): ', final_result_high_9)


##################################################################
###################################################################
##################################################################
##################################################################
# Create a data frame using pandas
# Columns: Simulation_#, CONOPs (protocol, frequency, environment), final_result_jam, final_result_high


# Columns
simulation_values = [
    'TLS_HF', 'TLS_VHF', 'TLS_UHF',
    'MLS_HF', 'MLS_VHF', 'MLS_UHF',
    'PSK_HF', 'PSK_VHF', 'PSK_UHF',
]

# data
data = {
    'Simulation': simulation_values,
    'Jamming': [ 
        final_result_jam_1, final_result_jam_2, final_result_jam_3,
        final_result_jam_4, final_result_jam_5, final_result_jam_6, 
        final_result_jam_7, final_result_jam_8,final_result_jam_9
    ],
    'Highjacking': [
        final_result_high_1, final_result_high_2, final_result_high_3,
        final_result_high_4, final_result_high_5, final_result_high_6,
        final_result_high_7, final_result_high_8,final_result_high_9
    ]
}

# DataFrame
df = pd.DataFrame(data)

print(df)

plt.rcParams.update({'font.size': 14})
# Save the data frame to a csv file
#df.to_csv('results.csv', index=False)

# Previous results
print ("\n\nThe previous results presented the following:\n")

print("The best jamming resilience was achieved by MLS and PSK\n")
print("The resilience results for jamming for TLS were not good\n\n")
print("The best highjacking resilience was achieved by MLS\n")
print ("The worst highjacking resilience was achieved by PSK\n")


# Plot with bar graph
fig, ax = plt.subplots(figsize=(10, 6))
df.plot(x='Simulation', y=['Jamming', 'Highjacking'], kind='bar', ax=ax)

# Custom y-axis labels for vulnerability levels
ax.set_yticks([])
ax.set_yticklabels('')
ax.set_ylabel('Vulnerability', fontsize=18)

# Title and format x-axis labels horizontally
plt.title('Jamming and Highjacking Vulnerability', fontsize=20)
plt.xticks(rotation=0,fontsize=12)
ax.set_xlabel('Simulation', fontsize=18)
plt.show()






