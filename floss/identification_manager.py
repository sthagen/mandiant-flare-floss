# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import logging
import operator
from typing import List, Tuple

from floss.plugins import mov_plugin, arithmetic_plugin, library_function_plugin, function_meta_data_plugin

logger = logger = logging.getLogger(__name__)


class IdentificationManager(object):
    """
    IdentificationManager runs identification plugins and computes
     the weights of their results.
    """

    # this defines the weight of each plugin
    # positive values mark functions likely decoding routines, while
    # negative values mark functions as not-decoding routines
    PLUGIN_WEIGHTS = {
        "XORPlugin": 0.5,
        "ShiftPlugin": 0.5,
        "MovPlugin": 0.3,
        "FunctionCrossReferencesToPlugin": 0.2,
        "FunctionArgumentCountPlugin": 0.2,
        "FunctionBlockCountPlugin": 0.025,
        "FunctionInstructionCountPlugin": 0.025,
        "FunctionSizePlugin": 0.025,
        "FunctionRecursivePlugin": 0.025,
        "FunctionIsThunkPlugin": -1.0,
        "FunctionIsLibraryPlugin": -1.0,
    }

    def __init__(self, vw):
        self.vw = vw
        self.candidate_functions = {}
        self.candidates_weighted = None

    def run_plugins(self, plugins, functions, raw_data=False):
        for plugin in plugins:
            decoder_candidates = plugin.identify(self.vw, functions)
            if raw_data:
                self.merge_candidates(str(plugin), decoder_candidates)
            else:
                scored_candidates = plugin.score(decoder_candidates, self.vw)
                self.merge_candidates(str(plugin), scored_candidates)

    def merge_candidates(self, plugin_name, plugin_candidates):
        """
        Merge data from all plugins into candidate_functions dictionary.
        """
        if not plugin_candidates:
            return self.candidate_functions

        for candidate_function in plugin_candidates:
            if candidate_function in self.candidate_functions.keys():
                logger.debug("Function at 0x%08X is already in candidate list, merging", candidate_function)
                self.candidate_functions[candidate_function][plugin_name] = plugin_candidates[candidate_function]
            else:
                logger.debug("Function at 0x%08X is new, adding", candidate_function)
                self.candidate_functions[candidate_function] = {}
                self.candidate_functions[candidate_function][plugin_name] = plugin_candidates[candidate_function]

    def apply_plugin_weights(self):
        """
        Return {effective_function_address: weighted_score}, the weighted score is a sum of the score a
        function received from each plugin multiplied by the plugin's weight. The
        :return: dictionary storing {effective_function_address: total score}
        """
        functions_weighted = {}
        for candidate_function, plugin_score in self.candidate_functions.items():
            logger.debug("0x%08X" % candidate_function)
            total_score = 0.0
            for plugin_name, score in plugin_score.items():
                if plugin_name not in self.PLUGIN_WEIGHTS.keys():
                    raise Exception("Plugin weight not found: %s" % plugin_name)
                logger.debug(
                    "[%s] %.05f (weight) * %.05f (score) = %.05f"
                    % (plugin_name, self.PLUGIN_WEIGHTS[plugin_name], score, self.PLUGIN_WEIGHTS[plugin_name] * score)
                )
                total_score = total_score + (self.PLUGIN_WEIGHTS[plugin_name] * score)
            logger.debug("Total score: %.05f\n" % total_score)
            functions_weighted[candidate_function] = total_score

        self.candidates_weighted = functions_weighted

    def sort_candidates_by_score(self):
        # via http://stackoverflow.com/questions/613183/sort-a-python-dictionary-by-value
        return sorted(self.candidates_weighted.items(), key=operator.itemgetter(1), reverse=True)

    def get_top_candidate_functions(self, n=10):
        return [(fva, score) for fva, score in self.sort_candidates_by_score()[:n]]

    def get_candidate_functions(self):
        return self.candidate_functions


def identify_decoding_functions(vw, functions: List[int], count: int) -> List[Tuple[int, int]]:
    """
    Identify the functions most likely to be decoding routines.

    arguments:
      functions: the functions to consider as potential decoding routines
      count: the max number of results to return

    returns:
      list of tuples (score, address)
    """
    identification_manager = IdentificationManager(vw)
    identification_manager.run_plugins(get_all_plugins(), functions)
    identification_manager.apply_plugin_weights()
    return identification_manager.get_top_candidate_functions(count)


def get_all_plugins():
    """
    Return all plugins to be run.
    """
    ps = list()
    ps.append(function_meta_data_plugin.FunctionCrossReferencesToPlugin())
    ps.append(function_meta_data_plugin.FunctionArgumentCountPlugin())
    ps.append(function_meta_data_plugin.FunctionIsThunkPlugin())
    ps.append(function_meta_data_plugin.FunctionBlockCountPlugin())
    ps.append(function_meta_data_plugin.FunctionInstructionCountPlugin())
    ps.append(function_meta_data_plugin.FunctionSizePlugin())
    ps.append(function_meta_data_plugin.FunctionRecursivePlugin())
    ps.append(library_function_plugin.FunctionIsLibraryPlugin())
    ps.append(arithmetic_plugin.XORPlugin())
    ps.append(arithmetic_plugin.ShiftPlugin())
    ps.append(mov_plugin.MovPlugin())
    return ps
