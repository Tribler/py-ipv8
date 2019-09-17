from __future__ import absolute_import, division

import math
from collections import namedtuple
from random import shuffle


Option = namedtuple('Option', ['value', 'obj'])
ReferenceFuncPoint = namedtuple('ReferenceFuncPoint', ['x', 'y'])


def unweigthed_pdf(x, X, bandwidth):
    """
    Given a 1D point x, a set of 1D bin center points X and the kernel bandwith, calculate the sum of the contributions
    of x for each of the points in X.

    :param x: the point to check the contribution for
    :type x: float
    :param X: the measuring points of the contribution
    :type X: [float]
    :param bandwidth: the kernel bandwith for the kernel estimate
    :type bandwidth: float
    :return: the contribution of x to X
    :rtype: float
    """
    return sum((math.sqrt(2 * math.pi * bandwidth ** 2) ** -1)
               * math.exp(-((x - x_i) ** 2) / (2 * bandwidth ** 2))
               for x_i in X)


def weighted_pdf(x, X, falloff):
    """
    Given a 1D point x, a set of 1D bin center points X and the kernel bandwith, calculate the sum of the contributions
    of x for each of the points in X. Normalize the result to 1.0.

    :param x: the point to check the contribution for
    :type x: float
    :param X: the measuring points of the contribution
    :type X: [float]
    :param falloff: the kernel bandwith for the kernel estimate
    :type falloff: float
    :return: the contribution of x to X
    :rtype: float
    """
    return unweigthed_pdf(x, X, falloff) / unweigthed_pdf(x, [x], falloff)


def get_error(references, included, option, falloff=0.025):
    """
    Get the error of including an option next to the already included options, given some reference points.
    We punish values over the reference point twice as much as those under the reference point.

    :param references: the requested value per measurement point
    :type references: [ReferenceFuncPoint]
    :param included: the already included options
    :type included: [float]
    :param option: the option to evaluate
    :type option: Option
    :param falloff: the kernel bandwith for the kernel estimate
    :type falloff: float
    :return: the error for the given option
    :rtype: float
    """
    errors = []
    for i in range(len(references)):
        x, y = references[i]
        d = weighted_pdf(x, included + ([option.value] if option is not None else []), falloff)
        e = y - d
        if d > y:
            e *= -2
        errors.append(e)
    return sum(errors)


def optimal_choice(references, included, options, falloff=0.025):
    """
    Given reference values and already included options, select the best fit from the given options.

    :param references: the requested value per measurement point
    :type references: [ReferenceFuncPoint]
    :param included: the already included options
    :type included: [float]
    :param options: the options to evaluate
    :type options: [Option]
    :param falloff: the kernel bandwith for the kernel estimate
    :type falloff: float
    :return: the best option to include, if it exists
    :rtype: Option or None
    """
    best_option = None
    best_mse = None
    for option in [None] + options:
        mse = get_error(references, included, option, falloff)
        if best_mse is None or mse < best_mse or (best_option is None and mse == best_mse):
            best_option = option
            best_mse = mse
    return best_option


def generate_reference(func, x_coords, peer_count):
    """
    Given a function and the points on which to evaluate, generate reference points.
    Normalize the function to fit a certain target count, such that the sum of all bins equals the requested peer count.

    :param func: the function to seed the bins with
    :type func: function
    :param x_coords: the x-coordinates to evaluate the given function
    :type x_coords: [float]
    :param peer_count: the total amount of requested peers
    :type peer_count: int
    :return: the reference points to use for the kernel density estimation
    :rtype: [ReferenceFuncPoint]
    """
    modifier = peer_count / sum(func(x) for x in x_coords)  # Make sure ceil doesn't clip
    distribution = [sum(weighted_pdf(x, x_coords, 0.025) for _ in range(int(math.ceil(modifier * func(x)))))
                    for x in x_coords]
    modifier = sum(distribution) / len(x_coords)
    return [ReferenceFuncPoint(x, modifier * func(x)) for x in x_coords]


class PeerSelector(object):
    """
    Class to aid with selecting weighted peers to fit a weighted distribution and to remove peers to fit a given
    weighted distribution.
    """

    def __init__(self, reference_points, included=None):
        """
        Create new PeerSelector from a set of reference points.
        For removal, give a set of already included peers.

        :param reference_points: the reference points which this selector is based on
        :type reference_points: [ReferenceFuncPoint]
        :param included: the optionally already included options
        :type included: [Option]
        """
        if not included:
            self.included = []
            self._included_values = []
        else:
            self.included = included
            self._included_values = [option.value for option in included]
        self.reference = reference_points

    def decide(self, options, falloff=0.025):
        """
        Return the optimal option from the given options to include, if it exists.

        :param options: the available options
        :type options: [Option]
        :return: the optimal choice
        :rtype: Option or None
        """
        shuffle(options)
        choice = optimal_choice(self.reference, self._included_values, options, falloff)
        if choice is not None:
            self.included.append(choice)
            self._included_values.append(choice.value)
        return choice

    def current_worst(self):
        """
        Get the current worst included option.

        :return: the current worst included options
        :rtype: Option
        """
        current_worst = None
        current_worst_mse = None
        for option in self.included:
            if option is None:
                continue
            values = [self.included[i].value for i in range(len(self.included))
                      if i != self.included.index(option) and option is not None]
            mse = get_error(self.reference, values, option)
            if current_worst is None or mse > current_worst_mse:
                current_worst = option
                current_worst_mse = mse
        return current_worst
