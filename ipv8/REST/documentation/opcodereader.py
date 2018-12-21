from __future__ import print_function

import dis, os, struct, sys

from six import integer_types


unary_ops = {
    'UNARY_POSITIVE': '+%s',
    'UNARY_NEGATIVE': '-%s',
    'UNARY_NOT': 'not %s',
    'UNARY_CONVERT': '`%s`',
    'UNARY_INVERT': '~%s',
    'GET_ITER': 'iter(%s)'
}


binary_ops = {
    'BINARY_POWER': '%s ** %s',
    'BINARY_MULTIPLY': '%s * %s',
    'BINARY_DIVIDE': '%s / %s',
    'BINARY_FLOOR_DIVIDE': '%s // %s',
    'BINARY_TRUE_DIVIDE': '%s / %s',
    'BINARY_MODULO': '%s \% %s',
    'BINARY_ADD': '%s + %s',
    'BINARY_SUBTRACT': '%s - %s',
    'BINARY_SUBSCR': '%s[%s]',
    'BINARY_LSHIFT': '%s << %s',
    'BINARY_RSHIFT': '%s >> %s',
    'BINARY_AND': '%s & %s',
    'BINARY_XOR': '%s ^ %s',
    'BINARY_OR': '%s | %s'
}


def unconstant(serialized):
    """
    Convert a small-endian number to int, otherwise returns None.
    """
    if len(serialized) == 8:
        return struct.unpack('<Q', serialized)[0]
    if len(serialized) == 4:
        return struct.unpack('<I', serialized)[0]
    if len(serialized) == 2:
        return struct.unpack('<H', serialized)[0]
    if len(serialized) == 1:
        return struct.unpack('<B', serialized)[0]
    return None


def pretty_constant(constant):
    if isinstance(constant, integer_types):
        return str(constant)
    return repr(constant)


def on_demand_parentheses(content):
    return "(%s)" % content if " " in content and not (content.startswith('(') and content.endswith(')')) else content


def consume_code(input_buffer):
    """
    Keep consuming more of the input buffer until it forms a valid operation.
    """
    index = 1
    while True:
        old_stdout = sys.stdout
        try:
            with open(os.devnull, 'w') as f:
                sys.stdout = f
                dis.dis(input_buffer[0:index])
            break
        except:
            index += 1
        finally:
            sys.stdout = old_stdout
    return input_buffer[:index], input_buffer[index:]


def to_instruction_list(input_buffer):
    """
    Consume an input buffer to form a list of instructions (tuples of opcode names and arguments).
    """
    instructions = []
    remainder = input_buffer
    while remainder:
        inst, remainder = consume_code(remainder)
        instructions.append((dis.opname[ord(inst[0])], unconstant(inst[1:])))
    return instructions


def pretty_str_instructions(global_names, local_names, constants, instructions):
    """
    Replay the stack operations to form a human readable string.
    """
    stack = []
    for instruction in instructions:
        op, arg = instruction
        if op == 'LOAD_GLOBAL':
            stack.append(global_names[arg])
            continue
        if op == 'LOAD_FAST':
            stack.append(local_names[arg])
            continue
        if op == 'LOAD_ATTR':
            stack.append('.' + global_names[arg])
            continue
        if op == 'LOAD_CONST':
            stack.append(pretty_constant(constants[arg]))
            continue
        if op == 'CALL_FUNCTION':
            stack.append(", ".join(reversed([stack.pop() for _ in range(arg)])))
            continue
        if op in binary_ops:
            a2, a1 = on_demand_parentheses(stack.pop()), on_demand_parentheses(stack.pop())
            stack.append(binary_ops[op] % (a1, a2))
            continue
        if op in unary_ops:
            a1 = on_demand_parentheses(stack.pop())
            stack.append(unary_ops[op] % (a1, ))
            continue
        if op == 'COMPARE_OP':
            a2, a1 = on_demand_parentheses(stack.pop()), on_demand_parentheses(stack.pop())
            stack.append('%s %s %s' % (a1, dis.cmp_op[arg], a2))
            continue
        if op == 'RETURN_VALUE':
            break
        raise RuntimeError("Unknown operation %s(%s) encountered" % (op, arg))
    return ''.join(stack)


def pretty_str_simple_lambda(lambda_func):
    """
    Inspect the byte code for the given lambda function and turn it into a human readable string.
    """
    raw = lambda_func.func_code.co_code
    constants = lambda_func.func_code.co_consts
    func_globals = lambda_func.func_code.co_names
    func_locals = lambda_func.func_code.co_varnames
    instructions = to_instruction_list(raw)
    return pretty_str_instructions(func_globals, func_locals, constants, instructions)


__all__ = ['pretty_str_simple_lambda']
