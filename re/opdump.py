"""HELPER FUNCTIONS"""
def get_function_instructions(func):
    listing = currentProgram.getListing()
    func_body = func.getBody()
    return listing.getInstructions(func_body, True)

def check_for_instructions(func, required_instructions):
    func_instructions = get_function_instructions(func)
    func_instructions = set(i.getMnemonicString().upper() for i in func_instructions)
    if len(func_instructions) == 3:
        if all(i.upper() in func_instructions for i in required_instructions):
            return True

def setup_emulator(func):
    from ghidra.app.emulator import EmulatorHelper
    emulator = EmulatorHelper(currentProgram)
    entry_point = func.getEntryPoint()
    emulator.writeRegister(emulator.getPCRegister(), entry_point.getOffset())
    return emulator

def get_register_value(func, register):
    emulator = setup_emulator(func)
    instructions = get_function_instructions(func)

    MAX_STEPS = 1000  # Safeguard against infinite loops
    for step_count, instruction in enumerate(instructions):
        if step_count > MAX_STEPS:
            print("Exceeded maximum number of steps")
            break
            
        if instruction.getMnemonicString().upper() == "RET":
            value = emulator.readRegister(register)
            emulator.dispose()
            return value
            
        emulator.step(monitor)
    emulator.dispose()
    print("RET instruction not found within step limit")
    return None

def output_to_file(filepath, content):
    import json
    with open(filepath, 'w') as file:
        json.dump(content, file, indent=4)


"""MAIN EXECUTION LOGIC"""
main_dict = {}
function_manager = currentProgram.getFunctionManager()
functions = [func for func in function_manager.getFunctions(True) if func.getName() == 'GetTypeCode']
for func in functions:
    classname = func.getParentNamespace().getName()

    valid = check_for_instructions(func, ['MOV', 'MOVK'])
    if valid: 
        w0 = get_register_value(func, 'w0')
        op_code = w0
        print(op_code)
        main_dict[classname] = op_code
        # if int(op_code) == 4256798260:
        #     print("OPCODE ENTRY: ", func.getEntryPoint())
        #     print("opcode: ", op_code)
        #     add_to_output(classname, "op_code", op_code)
            


opdump_filepath = 'C://al//assets//re//opdump.json'
output_to_file(opdump_filepath, main_dict)
print("DONE! Check {}".format(opdump_filepath))