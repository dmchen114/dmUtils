import os
import sys

current_dir = os.path.dirname(__file__)
root_dir  = os.path.normpath(os.path.join(current_dir, os.pardir))
output_dir = os.path.join(os.path.abspath(root_dir), 'building')

sys.path.insert(0, os.path.join(root_dir, 'tools', 'gyp', 'pylib'))
import gyp

def run_gyp(args):
    #print args
    rc = gyp.main(args)
    if rc != 0:
        print 'Error running GYP'
        sys.exit(rc)

if __name__ == '__main__':
    args = sys.argv[1:]
    args.append(os.path.join(os.path.abspath(root_dir), 'building/dmUtils.gyp'))
    args.extend(['--depth='+root_dir])
    if sys.platform != 'win32' and 'ninja' not in args:
        # Tell make to write its output into the same dir
        args.extend(['-Goutput_dir=' + output_dir])

    run_gyp(list(args));
