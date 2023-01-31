# Copyright 2018 Iguazio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from abc import ABC
from typing import Set

from transformers import Trainer, TrainerCallback

from mlrun.frameworks._common import CommonTypes, MLRunInterface


class HFTrainerMLRunInterface(MLRunInterface, ABC):
    """
    Interface for adding MLRun features for tensorflow keras API.
    """

    # MLRun's context default name:
    DEFAULT_CONTEXT_NAME = "mlrun-huggingface"

    # Attributes to replace so the MLRun interface will be fully enabled.
    _REPLACED_METHODS = [
        "train",
        # "evaluate"
    ]

    @classmethod
    def add_interface(
        cls,
        obj: Trainer,
        restoration: CommonTypes.MLRunInterfaceRestorationType = None,
    ):
        """
        Enrich the object with this interface properties, methods and functions, so it will have this TensorFlow.Keras
        MLRun's features.

        :param obj:                     The object to enrich his interface.
        :param restoration: Restoration information tuple as returned from 'remove_interface' in order to
                                        add the interface in a certain state.
        """
        super(HFTrainerMLRunInterface, cls).add_interface(
            obj=obj, restoration=restoration
        )

    @classmethod
    def mlrun_train(cls):
        """
        MLRun's tf.keras.Model.fit wrapper. It will setup the optimizer when using horovod. The optimizer must be
        passed in a keyword argument and when using horovod, it must be passed as an Optimizer instance, not a string.

        :raise MLRunInvalidArgumentError: In case the optimizer provided did not follow the instructions above.
        """

        def wrapper(self: Trainer, *args, **kwargs):
            # Restore the evaluation method as `train`` will use it:
            # cls._restore_attribute(obj=self, attribute_name="evaluate")

            # Call the original fit method:
            result = self.original_train(*args, **kwargs)

            # Replace the evaluation method again:
            # cls._replace_function(obj=self, function_name="evaluate")

            return result

        return wrapper
