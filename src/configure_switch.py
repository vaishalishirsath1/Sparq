"""
Author: Vaishali Shirsath
Email ID: vaishalishirsath1@gmail.com
Date: 31.05.2023

Description:
This Python script utilizes P4Runtime API and gRPC to interact with a P4 switch. It starts with importing necessary libraries, including protobuf, 
gRPC, P4RuntimeClient, and others. It then establishes a connection with the P4 switch using P4RuntimeClient, specifying parameters like the device ID 
and election ID. The gRPC address of the P4 switch is also defined. The script includes a series of helper functions to facilitate the interaction with 
the P4 switch:

    1. setup_p4_pipeline: Reads and parses a P4 program and a P4Info file, sets up a gRPC channel and P4RuntimeStub instance, and configures the forwarding 
    pipeline of the P4 switch using the P4RuntimeStub instance.
    2. get_id: Searches for the ID of a specific entity (table, action, or header field) in the P4Info data.
    3. insert_syn_flag_entry: Creates a table entry that matches the SYN flag of TCP packets and forwards them to the controller.
    4. insert_default_drop_entry: Creates a default table entry that drops all packets which do not match any other entries in the table (in this case, 
    non-SYN TCP packets).

Finally, the script executes the setup of the P4 pipeline, inserts the SYN flag matching entry, and inserts the default drop entry into the P4 switch.

Disclaimer:
This code is provided for educational and informational purposes only. The developer assume no responsibility for any errors, omissions, or inaccuracies 
in the information provided by this application.Users should exercise caution when using this code in a production environment.The developer shall not be 
held liable for any damages, losses, or consequences resulting from the use of, or reliance on, this code. Users are advised to carefully read and understand 
the code before using it, and to consider the potential impact on their network environment. Additionally, users should take appropriate measures to secure 
their networks and implement other complementary security solutions for comprehensive protection.
"""

# Import the required libraries
from google.protobuf import text_format
import grpc
from p4runtime_sh.p4runtime import P4RuntimeClient
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1.p4info_pb2 import P4Info
import os
from time import sleep

# Define the necessary configurations
election_id = (1, 0)  # You can use any unique election_id here
device_id = 0  # Use the same device_id for the same P4 switch
grpc_addr = "127.0.0.1:50051"

print("Creating a P4RuntimeClient instance")
sleep(0.2)
# Create a P4RuntimeClient instance
p4_runtime_client = P4RuntimeClient(device_id, grpc_addr, election_id)

# Function to set up the P4 pipeline
def setup_p4_pipeline(p4_client, p4_program_path, p4info_path):
    print("Reading the P4 program and P4Info files")
    sleep(0.2)
    # Read the P4 program and P4Info files
    with open(p4_program_path, 'rb') as f:
        p4_program = f.read()
    with open(p4info_path, 'r') as f:
        p4info_raw = f.read()

    print("Parsing the P4Info file")
    sleep(0.2)
    # Parse the content of the p4info file
    p4info = P4Info()
    text_format.Parse(p4info_raw, p4info)

    # Update the p4info attribute of the p4_client object
    p4_client.p4info = p4info
    
    print("Creating a gRPC channel and a P4RuntimeStub instance")
    sleep(0.2)
    # Create a gRPC channel and a P4RuntimeStub instance
    channel = grpc.insecure_channel(grpc_addr)
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

    print("Preparing the forwarding pipeline config")
    sleep(0.2)
    # Prepare the forwarding pipeline config
    config = p4runtime_pb2.ForwardingPipelineConfig(
        p4info=p4info,  # Pass the parsed p4info object here
        p4_device_config=p4_program
    )

    print("Setting the forwarding pipeline config")
    sleep(0.2)
    # Set the forwarding pipeline config using the P4RuntimeStub instance
    request = p4runtime_pb2.SetForwardingPipelineConfigRequest(
        election_id=p4runtime_pb2.Uint128(high=election_id[0], low=election_id[1]), # Create a Uint128 object here
        device_id=p4_client.device_id,
        config=config, # Use the singular 'config' field
        action=p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
    )
    stub.SetForwardingPipelineConfig(request)

    print("Returning the stub")
    sleep(0.2)
    print(" ")
    # Return the stub
    return stub

# Function to get the id of a P4Info entity
def get_id(p4info, entity_type, entity_name):
    print(f"Getting ID for : {entity_type} {entity_name}")
    sleep(0.2)
    # Handle different entity types
    if entity_type == "table":
        entities = p4info.tables
    elif entity_type == "action":
        entities = p4info.actions
    elif entity_type == "header_field":
        for table in p4info.tables:
            for field in table.match_fields:
                if entity_name == field.name:
                    print(f"Found : {entity_type} {entity_name} with id {field.id} and bitwidth {field.bitwidth}")
                    return field.id, field.bitwidth
    else:
        print(f"Error: Unsupported entity_type {entity_type}")
        return None

    # Search for the entity
    for entity in entities:
        if entity_name == entity.preamble.name:
            print(f"Found : {entity_type} {entity_name} with id {entity.preamble.id}")
            sleep(0.2)
            return entity.preamble.id

    # If the entity is not found, return None
    print(f"Error: {entity_type} {entity_name} not found")
    return None

# Function to insert a table entry for SYN flag
def insert_syn_flag_entry(p4_client, stub, syn_flag_value):
    # Define the names of the table and action
    table_name = "MyIngress.syn_flag_table"
    action_name = "MyIngress.forward_to_controller"
    
    # Get the ID of the table, header field, and action
    table_id = get_id(p4_client.p4info, "table", table_name)
    header_field_id, field_offset = get_id(p4_client.p4info, "header_field", "hdr.tcp.flags")
    action_id = get_id(p4_client.p4info, "action", action_name)

    print(f"Table ID: {table_id}, Header Field ID: {header_field_id}, Field Offset: {field_offset}, Action ID: {action_id}")
    sleep(0.2)

    # Define the mask for the SYN flag
    mask = 0x002

    # Create a match field to match the SYN flag in the TCP header
    match_field = p4runtime_pb2.FieldMatch(
        field_id=header_field_id,
        ternary=p4runtime_pb2.FieldMatch.Ternary(
            value=syn_flag_value.to_bytes(1, byteorder="big"),  # Convert SYN flag value to bytes
            mask=(0x02).to_bytes(1, byteorder="big")  # Convert mask to bytes
        )
    )

    print("********** Creating Flag Table **********")
    sleep(0.2)    

    # Create a table entry with the match field and action
    table_entry = p4runtime_pb2.TableEntry(
        table_id=table_id,
        match=[match_field],
        action=p4runtime_pb2.TableAction(
            action=p4runtime_pb2.Action(
                action_id=action_id,
            )
        ),
        priority=100  # Set priority value for the entry
    )

    print(f"Flag Table Entry: {table_entry}")

    print("********** Updating Flag Table **********")
    sleep(0.25)
    # Create an update for the table entry
    update = p4runtime_pb2.Update(
        type=p4runtime_pb2.Update.INSERT,
        entity=p4runtime_pb2.Entity(table_entry=table_entry)
    )

    print(f"Flag Table Update: {update}")
    sleep(0.2)

    print("********** Writing Flag Request **********")
    sleep(0.2)
    
    # Create a write request with the update
    request = p4runtime_pb2.WriteRequest(
        device_id=p4_client.device_id,
        election_id=p4runtime_pb2.Uint128(high=p4_client.election_id[0], low=p4_client.election_id[1]),  # Convert the tuple to Uint128 object
        updates=[update]
    )

    print(f"Flag Request: {request}")
    sleep(0.2)
    # Try to write the table entry using the P4RuntimeStub instance
    try:
        stub.Write(request)
        sleep(0.2)
        print("Successfully wrote the flag request.")
        print(" ")
    except grpc.RpcError as e:  # Handle possible exceptions
        print(f"An error occurred while writing the table entry: {e}")
        print(f"Status code: {e.code()}")
        print(f"Details: {e.details()}")
        print(f"Debug error string: {e.debug_error_string()}")
        raise  # Reraise the exception

# Function to insert a default table entry to drop packets
def insert_default_drop_entry(p4_client, stub):
    # Define the names of the table and action
    table_name = "MyIngress.syn_flag_table"
    action_name = "MyIngress._drop"
    
    # Get the ID of the table and action
    table_id = get_id(p4_client.p4info, "table", table_name)
    action_id = get_id(p4_client.p4info, "action", action_name)

    print(f"Table ID: {table_id}, Action ID: {action_id}")
    sleep(0.2)

    print("********** Creating Default Drop Table **********")
    sleep(0.2)

    # Create a table entry with the action and a lower priority than the entry for SYN flag
    table_entry = p4runtime_pb2.TableEntry(
        table_id=table_id,
        action=p4runtime_pb2.TableAction(
            action=p4runtime_pb2.Action(
                action_id=action_id,
            )
        ),
        priority=10  # Lower priority than the entry for SYN flag
    )

    print(f"Default Drop Table Entry: {table_entry}")

    print("********** Update Default Drop Table **********")
    sleep(0.2)

    # Create an update for the table entry
    update = p4runtime_pb2.Update(
        type=p4runtime_pb2.Update.INSERT,
        entity=p4runtime_pb2.Entity(table_entry=table_entry)
    )


    print(f"Update: {update}")
    sleep(0.2)

    print("********** Writing Default Drop request **********")
    sleep(0.2)

    # Create a write request with the update
    request = p4runtime_pb2.WriteRequest(
        device_id=p4_client.device_id,
        election_id=p4runtime_pb2.Uint128(high=p4_client.election_id[0], low=p4_client.election_id[1]),  # Convert the tuple to Uint128 object
        updates=[update]
    )

    print(f"Write Default Drop Request: {request}")
    sleep(0.2)

    # Try to write the table entry using the P4RuntimeStub instance
    try:
        stub.Write(request)
        print("Successfully wrote the Default Drop table.")
    except grpc.RpcError as e:  # Handle possible exceptions
        print(f"An error occurred while writing the table entry: {e}")
        print(f"Status code: {e.code()}")
        print(f"Details: {e.details()}")
        print(f"Debug error string: {e.debug_error_string()}")
        raise  # Reraise the exception

# Set up the P4 pipeline
print("===============Setting up the P4 pipeline===============")
sleep(0.2)
p4_program_path = os.path.join(os.path.dirname(__file__), 'output/spark.json')
p4info_path = os.path.join(os.path.dirname(__file__), 'output/spark.p4info')
stub = setup_p4_pipeline(p4_runtime_client, p4_program_path, p4info_path)

# Add the table entry for TCP SYN flag
print("===============Inserting table entry for SYN flag===============")
sleep(0.2)
insert_syn_flag_entry(p4_runtime_client, stub, 0x002)

# Add the default entry to drop non-SYN packets
print("Since we are only dealing with TCP Packet drop packets with other Protocol")
sleep(0.5)
print("=============== Inserting default drop entry to drop packets ===============")
sleep(0.2)
insert_default_drop_entry(p4_runtime_client, stub)
