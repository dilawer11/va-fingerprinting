import os
import argparse

from iotpackage.InvocationDetection import WindowGeneration, ClassifierTraining, ClassifierInferring
from iotpackage.__vars import InvocationDetectionConfig

CONFIG = InvocationDetectionConfig()

def mainWindows(args):
    if not os.path.isdir(args.input_dir):
        raise FileNotFoundError(f"input_dir='{args.input_dir}' not found.")

    window_gen = WindowGeneration(input_dir=args.input_dir, wsize=args.window_size,
                                  wstep=args.window_step, mark_true_in=args.mark_true_in, idle=args.idle)
    window_gen.start()
    return


def mainTrain(args):
    balance_samples = not args.no_balance_samples
    if not os.path.isdir(args.input_dir):
        raise FileNotFoundError(f'No such directory: {args.input_dir}')

    clf_train = ClassifierTraining(args.input_dir, args.setup_name, balance_samples=balance_samples)
    clf_train.run()
    return


def mainInfer(args):
    balance_samples = not args.no_balance_samples
    if not os.path.isdir(args.input_dir):
        raise FileNotFoundError(f'No such directory: {args.input_dir}')

    data_input_dir = args.input_dir
    model_input_dir = args.model_input_dir if args.model_input_dir is not None else data_input_dir

    data_setup_name = args.setup_name
    model_setup_name = args.setup_name if args.model_input_dir is not None else data_setup_name

    clf_infer = ClassifierInferring(data_input_dir=data_input_dir, data_setup_name=data_setup_name, balance_samples=balance_samples,
                                    model_input_dir=model_input_dir, model_setup_name=model_setup_name)
    clf_infer.run()
    return

def mainAutoTrain(args):
    # Add default window args
    args.window_size = CONFIG.WSIZE
    args.window_step = CONFIG.WSTEP
    args.mark_true_in = CONFIG.MARK_TRUE_IN
    args.idle = False

    # Add default train args
    args.setup_name = CONFIG.GET_SETUP_NAME()
    args.no_balance_samples = False

    mainWindows(args)
    mainTrain(args)
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="choose a sub command", dest='command')
    window_parser = subparsers.add_parser('windows', help="'windows' help")
    window_parser.add_argument(
        '-i', dest='input_dir', required=True, help="The input dataset base directory path")
    window_parser.add_argument('--window-size', default=CONFIG.WSIZE, type=int,
                               help=f"The size of the window from start to end in seconds. (default={CONFIG.WSIZE}")
    window_parser.add_argument('--window-step', default=CONFIG.WSTEP, type=int,
                               help=f"The step or how much each window moves in seconds. (default={CONFIG.WSTEP}")
    window_parser.add_argument('--mark-true-in', default=CONFIG.MARK_TRUE_IN, type=int,
                               help=f"In how many seconds from the window start should the invocation time fall in to mark true. (default={CONFIG.MARK_TRUE_IN})")
    window_parser.add_argument('--idle', action='store_true', default=False,
                               help="To create windows from idle traffic without invoke start times. (default=False). All windows will be marked as 0 or no invocation")

    train_parser = subparsers.add_parser('train', help="'train' help")
    train_parser.add_argument('-i', dest='input_dir',
                              required=True, help='The input dataset base directory path')
    train_parser.add_argument('-s', dest="setup_name", type=str, default=CONFIG.GET_SETUP_NAME(),
                              help="The setup name to use. By default uses the default setup name")
    train_parser.add_argument('--no-balance-samples', default=False, action='store_true', help="Whether or not to balance training data (equal sample)")

    infer_parser = subparsers.add_parser('infer', help="'infer' help")
    infer_parser.add_argument('-i', dest='input_dir',
                              required=True, help="The input dataset base directory path")
    infer_parser.add_argument('-s', dest='setup_name', type=str, default=CONFIG.GET_SETUP_NAME(),
                              help="The setup name to use. By default uses the default setup name")
    infer_parser.add_argument('--mi', dest='model_input_dir', default=None,
                              help="The input directory for the model. By default uses the same as input")
    infer_parser.add_argument('--ms', dest="model_setup_name", type=str, default=CONFIG.GET_SETUP_NAME(),
                              help="The setup name to use. By default uses the default setup name")
    infer_parser.add_argument('--no-balance-samples', default=False, action='store_true', help="Whether or not to min sample (equal sample)")

    auto_train_parser = subparsers.add_parser('auto-train', help="'auto-train' help")
    auto_train_parser.add_argument('-i', dest='input_dir',
                              required=True, help='The input dataset base directory path')

    args = parser.parse_args()

    if args.command == "train":
        mainTrain(args)
    elif args.command == "windows":
        mainWindows(args)
    elif args.command == "infer":
        mainInfer(args)
    elif args.command == "auto-train":
        mainAutoTrain(args)

    print("\nScript Completed Execution")