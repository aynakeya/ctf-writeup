import os
from pwn import *
import twophase.solver as sv

exe = ELF("./cube_patched_2")
context.log_level = "debug"
context.binary = exe
def log_print(*msg):
    log.info(" ".join(map(str,msg)))
lp = log_print
def start(local=False):
    if args.LOCAL or local:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("rev.chal.csaw.io", 5028)
    return r


def split_by_k(fmt:str,k):
    return [fmt[i:i+k] for i in range(0,len(fmt),k)]

standard_state_str = "U1U2U3U4U5U6U7U8U9 R1R2R3R4R5R6R7R8R9 F1F2F3F4F5F6F7F8F9 D1D2D3D4D5D6D7D8D9 L1L2L3L4L5L6L7L8L9 B1B2B3B4B5B6B7B8B9"
standard_state = split_by_k(standard_state_str.replace(" ",""),2)
alice_state_str = "D3L4B1F8U5F6L3D6D9 R9R4U3U4R5U8U1D8D7 U7R8B7L6F5L2R1U6B3 F3R2L1L8D5B8L9B2L7 F9D2F1B4L5F4D1D4U9 R3B6R7F2B5R6B9U2F7"
alice_state = split_by_k(alice_state_str.replace(" ",""),2)

alice_to_standard_map = dict(zip(alice_state,standard_state))
standard_alice_to_map = dict(zip(standard_state,alice_state))

standard_blocks = {}
standard_blocks_state_index = []

standard_block_pairs = [
('U5',),('F5',),('L5',),('R5',),('B5',),('D5',),
('F2','U8'),('F4','L6'),('F6','R4'),('F8','D2'),
('U6','R2'),('U4','L2'),('L8','D4'),('D6','R8'),
('R6','B4'),('B6','L4'),('B2','U2'),('B8','D8'),
('F1','L3','U7'),('F3','R1','U9'),('F7','L9','D1'),('F9','R7','D3'),
('U1','L1','B3'),('U3','R3','B1'),('D9','R9','B7'),('D7','L7','B9')
]

_pos_all = []
for p in standard_block_pairs:
    _pos_all.extend(p)

assert len(set(_pos_all)) == len(_pos_all)

for pair in standard_block_pairs:
    standard_blocks_state_index.append(
        tuple(standard_state.index(p) for p in pair)
        )
    plist = list(pair)
    plist.sort()
    key = "".join(x[0] for x in plist)
    key_pos_map = dict(zip(key,plist))
    standard_blocks[key] = key_pos_map

def get_pos_map(*colors):
    colors.sort()
    return

def get_cube_state(raw_cube:list):
    cube_state = [x for x in raw_cube]
    for indexes in standard_blocks_state_index:
        colors = [cube_state[i] for i in indexes]
        colors.sort()
        m = standard_blocks["".join(colors)]

        for i in indexes:
            cube_state[i] = m[cube_state[i]]
    return cube_state

def alice_state_to_standard(state):
    return [alice_to_standard_map[x] for x in state]

def get_cute_from_input(inputstr):
    inputstr = inputstr.replace(" ","")
    inputstr = inputstr.replace("Y","F").replace("R","U").replace("O","D").replace("G","L").replace("B","R").replace("W","B")
    return inputstr
alice_input = "O G WY R YG O OB B RR B RR O OR B WG Y GB R WY B GG O WG W G Y O YW G YO O RB W B Y W BW R Y "
alice_cube = get_cute_from_input(alice_input)

assert get_cube_state(alice_cube) == alice_state

assert alice_state_to_standard(alice_state) == standard_state

def get_steps_from_state(state):
    cube_string = [x[0] for x in state]
    # solve
    soln_str = sv.solve(cube_string, 15, 20)
    soln_str = soln_str[:soln_str.find("(")]
    lp("soln:")
    steps = []
    for step in soln_str.split(" "):
        if len(step) == 0:
            continue
        if step[1] == "2":
            steps.extend([step[0]]*2)
        elif step[1] == "1":
            steps.append(step[0])
        else:
            steps.append(step[0]+"'")
    return steps


def stringify_raw_input(data):
    value = ""
    one = ""
    two = ""
    three = ""
    four = ""
    five = ""
    counter = 0
    for i in data.replace(" ","").replace("\n", ""):
        if counter < 9:
            value += i
        elif counter < 12:
            one += i
        elif counter < 15:
            two += i
        elif counter < 18:
            three += i
        elif counter < 21:
            four += i
        elif counter < 24:
            one += i
        elif counter < 27:
            two += i
        elif counter < 30:
            three += i
        elif counter < 33:
            four += i
        elif counter < 36:
            one += i
        elif counter < 39:
            two += i
        elif counter < 42:
            three += i
        elif counter < 45:
            four += i
        else:
            five += i
        counter += 1
    value += four + three + five + two + one
    return value

def get_flag(local,max_step):
    io = start(local)
    io.recvuntil(b"20 moves or less?\n\n")
    raw_input = io.recvuntil(b"\n\nEnter your moves",drop=True)
    cube_input = stringify_raw_input(raw_input.decode())
    lp("cube raw",cube_input)
    cube = get_cute_from_input(cube_input)
    lp("cube",cube_input)
    cube_state = get_cube_state(cube)
    lp("cube state",cube_state)
    cube_state_std = alice_state_to_standard(cube_state)
    lp("cube state std",cube_state_std)
    steps = get_steps_from_state(cube_state_std)

    if len(steps) > max_step:
        lp("larger than max step: ", len(steps))
        io.close()
        return
    os.system("notify-send CUBECUBECUBECUBE")
    print(steps)
    io.interactive()
    # lp(steps,len(steps))
    # lp(io.recv())
    # for step in steps:
    #     io.sendline(step.encode())
    # io.sendline(b"#")
    # io.interactive()

while True:
    try:
        get_flag(False,20)
    except:
        print("failed :-(")

# while True:
#     pass
# after_input = ""
# after_cube = get_cute_from_input(after_input)
# after_state = get_cube_state(after_cube)
# after_state_std = alice_state_to_standard(after_state)

# soln_str = "L2 B2 D2 B2 U2 F1 L1 R3 U3 B3 L2 U3 F1 L1 F3 R2 F3 D1 F1 (19f)"
# print(soln_str)
# soln_str = soln_str[:soln_str.find("(")]

# steps = []
# for step in soln_str.split(" "):
#     if len(step) == 0:
#         continue
#     if step[1] == "2":
#         steps.extend([step[0]]*2)
#     elif step[1] == "1":
#         steps.append(step[0])
#     else:
#         steps.append(step[0]+"'")
# print(steps)
