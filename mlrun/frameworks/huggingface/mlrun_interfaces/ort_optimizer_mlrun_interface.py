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
import shutil
from abc import ABC
from typing import Dict

from optimum.onnxruntime import ORTOptimizer

import mlrun
from mlrun.frameworks._common import CommonTypes, MLRunInterface


class HFORTOptimizerMLRunInterface(MLRunInterface, ABC):
    """
    Interface for adding MLRun features for tensorflow keras API.
    """

    # MLRun's context default name:
    DEFAULT_CONTEXT_NAME = "mlrun-huggingface"

    # Attributes to be inserted so the MLRun interface will be fully enabled.
    _PROPERTIES = {
        "_auto_log": False,
        "_context": None,  # type: mlrun.MLClientCtx
        "_model_name": "model",
        "_tag": "",
        "_labels": None,  # type: Dict[str, str]
        "_extra_data": None,  # type: Dict
    }
    _METHODS = ["enable_auto_logging"]
    # Attributes to replace so the MLRun interface will be fully enabled.
    _REPLACED_METHODS = [
        "optimize",
    ]

    @classmethod
    def add_interface(
        cls,
        obj: ORTOptimizer,
        restoration: CommonTypes.MLRunInterfaceRestorationType = None,
    ):
        """
        Enrich the object with this interface properties, methods and functions, so it will have this TensorFlow.Keras
        MLRun's features.

        :param obj:                     The object to enrich his interface.
        :param restoration: Restoration information tuple as returned from 'remove_interface' in order to
                                        add the interface in a certain state.
        """
        super(HFORTOptimizerMLRunInterface, cls).add_interface(
            obj=obj, restoration=restoration
        )

    @classmethod
    def mlrun_optimize(cls):
        """
        MLRun's tf.keras.Model.fit wrapper. It will setup the optimizer when using horovod. The optimizer must be
        passed in a keyword argument and when using horovod, it must be passed as an Optimizer instance, not a string.

        :raise MLRunInvalidArgumentError: In case the optimizer provided did not follow the instructions above.
        """

        def wrapper(self: ORTOptimizer, *args, **kwargs):
            save_dir = cls._get_function_argument(
                self.optimize,
                argument_name="save_dir",
                passed_args=args,
                passed_kwargs=kwargs,
            )[0]

            # Call the original optimize method:
            result = self.original_optimize(*args, **kwargs)

            if self._auto_log:
                # Zip the onnx model directory:
                shutil.make_archive(
                    base_name="onnx_model",
                    format="zip",
                    root_dir=save_dir,
                )
                # Log the onnx model:
                self._context.log_model(
                    key="model",
                    db_key=self._model_name,
                    model_file="onnx_model.zip",
                    tag=self._tag,
                    framework="ONNX",
                    labels=self._labels,
                    extra_data=self._extra_data,
                )

            return result

        return wrapper

    def enable_auto_logging(
        self,
        context: mlrun.MLClientCtx,
        model_name: str = "model",
        tag: str = "",
        labels: Dict[str, str] = None,
        extra_data: dict = None,
    ):
        self._auto_log = True

        self._context = context
        self._model_name = model_name
        self._tag = tag
        self._labels = labels
        self._extra_data = extra_data