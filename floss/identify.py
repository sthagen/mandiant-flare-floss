# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import copy
import operator
import collections

import tqdm
import viv_utils

import floss.logging_
from floss.features.extract import (
    abstract_features,
    extract_insn_features,
    extract_function_features,
    extract_basic_block_features,
)
from floss.features.features import Arguments, BlockCount, InstructionCount

logger = floss.logging_.getLogger(__name__)


def get_function_api(f):
    ret_type, ret_name, call_conv, func_name, args = f.vw.getFunctionApi(int(f))

    return {
        "ret_type": ret_type,
        "ret_name": ret_name,
        "call_conv": call_conv,
        "func_name": func_name,
        "arguments": args,
    }


def get_function_meta(f):
    meta = f.vw.getFunctionMetaDict(int(f))

    return {
        "api": get_function_api(f),
        "size": meta.get("Size", 0),
        "block_count": meta.get("BlockCount", 0),
        "instruction_count": meta.get("InstructionCount", 0),
    }


def get_max_calls_to(vw, skip_thunks=True, skip_libs=True):
    calls_to = set()

    for fva in vw.getFunctions():
        if skip_thunks and is_thunk_function(vw, fva):
            continue

        # TODO skip_libs and is_library_function
        #     continue

        calls_to.add(len(vw.getXrefsTo(fva)))

    return max(calls_to)


def is_thunk_function(vw, function_address):
    return vw.getFunctionMetaDict(function_address).get("Thunk", False)


def get_function_score_weighted(features):
    return sum(feature.weighted_score() for feature in features) / sum(feature.weight for feature in features)


def get_top_functions(candidate_functions, count=10):
    return sorted(candidate_functions.items(), key=lambda x: operator.getitem(x[1], "score"), reverse=True)[:count]


def get_function_fvas(functions):
    return list(map(lambda p: p[0], functions))


def get_functions_with_tightloops(functions):
    return get_functions_with_features(
        functions, (floss.features.features.TightLoop, floss.features.features.KindaTightLoop)
    )


def get_functions_without_tightloops(functions):
    tloop_functions = get_functions_with_tightloops(functions)
    no_tloop_funcs = copy.copy(functions)
    for fva, _ in tloop_functions.items():
        del no_tloop_funcs[fva]
    return no_tloop_funcs


def get_functions_with_features(functions, features):
    functions_by_features = dict()
    for fva, function_data in functions.items():
        func_features = list(filter(lambda f: isinstance(f, features), function_data["features"]))
        if func_features:
            functions_by_features[fva] = func_features
    return functions_by_features


def find_decoding_function_features(vw, functions, disable_progress=False):
    decoding_candidate_functions = collections.defaultdict(float)

    meta = {
        "library_functions": {},
    }

    pbar = tqdm.tqdm
    if disable_progress:
        logger.info("identifying decoding function features...")
        # do not use tqdm to avoid unnecessary side effects when caller intends
        # to disable progress completely
        pbar = lambda s, *args, **kwargs: s

    functions = sorted(functions)
    n_funcs = len(functions)

    pb = pbar(
        functions, desc="finding decoding function features", unit=" functions", postfix="skipped 0 library functions"
    )
    with tqdm.contrib.logging.logging_redirect_tqdm(), floss.utils.redirecting_print_to_tqdm():
        for f in pb:
            function_address = int(f)

            if is_thunk_function(vw, function_address):
                continue

            if viv_utils.flirt.is_library_function(vw, function_address):
                # TODO handle j_j_j__free_base (lib function wrappers), e.g. 0x140035AF0 in d2ca76...
                # TODO ignore function called to by library functions
                function_name = viv_utils.get_function_name(vw, function_address)
                logger.debug("skipping library function 0x%x (%s)", function_address, function_name)
                meta["library_functions"][function_address] = function_name
                n_libs = len(meta["library_functions"])
                percentage = 100 * (n_libs / n_funcs)
                if isinstance(pb, tqdm.tqdm):
                    pb.set_postfix_str("skipped %d library functions (%d%%)" % (n_libs, percentage))
                continue

            f = viv_utils.Function(vw, function_address)

            function_data = {"meta": get_function_meta(f), "features": list()}

            # meta data features
            function_data["features"].append(BlockCount(function_data["meta"].get("block_count")))
            function_data["features"].append(InstructionCount(function_data["meta"].get("instruction_count")))
            function_data["features"].append(Arguments(function_data["meta"].get("api", []).get("arguments")))

            for feature in extract_function_features(f):
                function_data["features"].append(feature)

            for bb in f.basic_blocks:
                for feature in extract_basic_block_features(f, bb):
                    function_data["features"].append(feature)

                for insn in bb.instructions:
                    for feature in extract_insn_features(f, bb, insn):
                        function_data["features"].append(feature)

            for feature in abstract_features(function_data["features"]):
                function_data["features"].append(feature)

            function_data["score"] = get_function_score_weighted(function_data["features"])

            logger.debug("analyzed function 0x%x - total score: %f", function_address, function_data["score"])
            for feat in function_data["features"]:
                logger.trace("  %s", feat)

            decoding_candidate_functions[function_address] = function_data

        return decoding_candidate_functions, meta
