not_processed_stdin = ""
def stdin_stdout_communication(console_io_read_equivalent):
    global not_processed_stdin
    try:
        lines = console_io_read_equivalent.split('\n')
        if not lines:
            return
        if not_processed_stdin:
            lines[0] = not_processed_stdin + lines[0]
            not_processed_stdin = ""
        # if last line is not empty, it means that
        # '\n' wasn't at the end of the received text
        # so the last string should be saved for further processing
        if lines[-1] != "":
            not_processed_stdin = str(lines[-1])
        # either way the last line must be removed because either it's:
        # - empty (due to text ending with '\n')
        # - not complete message that should not be processed (due to lack of '\n' at the end)
        del lines[-1]
        
        for line in lines:
            print(line)
    except UnicodeDecodeError:
        print('WARNING: UnicodeDecodeError in stdin_stdout_communication')
    
# stdin_stdout_communication("abc")
stdin_stdout_communication("abc\nnew")
stdin_stdout_communication("text\ntest")
stdin_stdout_communication("123")
stdin_stdout_communication("")
stdin_stdout_communication("t\nasd")