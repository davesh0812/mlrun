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
# flake8: noqa  - this is until we take care of the F401 violations with respect to __all__ & sphinx
from typing import Dict, Union

import optimum.onnxruntime as optimum_ort
import transformers

import mlrun

from .callbacks import MLRunCallback
from .mlrun_interfaces import HFORTOptimizerMLRunInterface, HFTrainerMLRunInterface
from .model_server import HuggingFaceModelServer


def _apply_mlrun_on_trainer(
    trainer: transformers.Trainer,
    model_name: str = None,
    tag: str = "",
    context: mlrun.MLClientCtx = None,
    auto_log: bool = True,
    labels: Dict[str, str] = None,
    extra_data: dict = None,
    **kwargs
):
    # Get parameters defaults:
    if context is None:
        context = mlrun.get_or_create_ctx(HFTrainerMLRunInterface.DEFAULT_CONTEXT_NAME)

    HFTrainerMLRunInterface.add_interface(obj=trainer)

    if auto_log:
        trainer.add_callback(
            MLRunCallback(
                context=context,
                model_name=model_name,
                tag=tag,
                labels=labels,
                extra_data=extra_data,
            )
        )


def _apply_mlrun_on_optimizer(
    optimizer: optimum_ort.ORTOptimizer,
    model_name: str = None,
    tag: str = "",
    context: mlrun.MLClientCtx = None,
    auto_log: bool = True,
    labels: Dict[str, str] = None,
    extra_data: dict = None,
    **kwargs
):
    # Get parameters defaults:
    if context is None:
        context = mlrun.get_or_create_ctx(
            HFORTOptimizerMLRunInterface.DEFAULT_CONTEXT_NAME
        )

    HFORTOptimizerMLRunInterface.add_interface(obj=optimizer)

    if auto_log:
        optimizer.enable_auto_logging(
            context=context,
            model_name=model_name,
            tag=tag,
            labels=labels,
            extra_data=extra_data,
        )


def apply_mlrun(
    huggingface_object: Union[optimum_ort.ORTOptimizer, transformers.Trainer],
    model_name: str = None,
    tag: str = "",
    context: mlrun.MLClientCtx = None,
    auto_log: bool = True,
    labels: Dict[str, str] = None,
    extra_data: dict = None,
    **kwargs
):
    """
    Wrap the given model with MLRun's interface providing it with mlrun's additional features.

    :param huggingface_object: The model to wrap. Can be loaded from the model path given as well.
    :param model_name:         The model name to use for storing the model artifact. Default: "model".
    :param tag:                The model's tag to log with.
    :param context:            MLRun context to work with. If no context is given it will be retrieved via
                               'mlrun.get_or_create_ctx(None)'
    :param auto_log:           Whether to enable MLRun's auto logging. Default: True.
    """
    if isinstance(huggingface_object, transformers.Trainer):
        return _apply_mlrun_on_trainer(
            trainer=huggingface_object,
            model_name=model_name,
            tag=tag,
            context=context,
            auto_log=auto_log,
            labels=labels,
            extra_data=extra_data,
        )
    if isinstance(huggingface_object, optimum_ort.ORTOptimizer):
        return _apply_mlrun_on_optimizer(
            optimizer=huggingface_object,
            model_name=model_name,
            tag=tag,
            context=context,
            auto_log=auto_log,
            labels=labels,
            extra_data=extra_data,
        )
    raise mlrun.errors.MLRunInvalidArgumentError