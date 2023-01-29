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
import os
import shutil
import tempfile
from typing import Dict, List

import numpy as np
from plotly import graph_objects as go
from transformers import (
    PreTrainedModel,
    PreTrainedTokenizer,
    TrainerCallback,
    TrainerControl,
    TrainerState,
    TrainingArguments,
)

import mlrun
from mlrun.artifacts import Artifact, PlotlyArtifact


class HyperparametersKeys:  # FUTURE USE
    """
    For easy noting on which object to search for the hyperparameter to track with the logging callback in its
    initialization method.
    """

    MODEL = "model"
    TRAIN_DATALOADER = "train_dataloader"
    EVAL_DATALOADER = "eval_dataloader"
    TOKENIZER = "tokenizer"
    OPTIMIZER = "optimizer"
    LR_SCHEDULER = "lr_scheduler"
    CUSTOM = "custom"


class MLRunCallback(TrainerCallback):
    """
    Callback for collecting logs during training / evaluation of the `Trainer` API.
    """

    def __init__(
        self,
        context: mlrun.MLClientCtx = None,
        model_name: str = "model",
        tag: str = "",
        labels: Dict[str, str] = None,
        extra_data: dict = None,
    ):
        super().__init__()

        # Store the configurations:
        self._context = (
            context
            if context is not None
            else mlrun.get_or_create_ctx("./mlrun-huggingface")
        )
        self._model_name = model_name
        self._tag = tag
        self._labels = labels
        self._extra_data = extra_data if extra_data is not None else {}

        # Set up the logging mode:
        self._is_training = False
        self._steps: List[List[int]] = []
        self._metric_scores: Dict[str, List[float]] = {}
        self._artifacts: Dict[str, Artifact] = {}

    def on_epoch_begin(
        self,
        args: TrainingArguments,
        state: TrainerState,
        control: TrainerControl,
        **kwargs,
    ):
        self._steps.append([])

    def on_epoch_end(
        self,
        args: TrainingArguments,
        state: TrainerState,
        control: TrainerControl,
        **kwargs,
    ):
        self._log_metrics()

    def on_log(
        self,
        args: TrainingArguments,
        state: TrainerState,
        control: TrainerControl,
        logs: Dict[str, float] = None,
        **kwargs,
    ):
        recent_logs = state.log_history[-1].copy()

        recent_logs.pop("epoch")
        current_step = int(recent_logs.pop("step"))
        if current_step not in self._steps[-1]:
            self._steps[-1].append(current_step)

        for metric_name, metric_score in recent_logs.items():
            if metric_name.startswith("train_"):
                if metric_name.split("train_")[1] not in self._metric_scores:
                    self._metric_scores[metric_name] = [metric_score]
                continue
            if metric_name not in self._metric_scores:
                self._metric_scores[metric_name] = []
            self._metric_scores[metric_name].append(metric_score)

    def on_train_begin(
        self,
        args: TrainingArguments,
        state: TrainerState,
        control: TrainerControl,
        **kwargs,
    ):
        self._is_training = True

    def on_train_end(
        self,
        args: TrainingArguments,
        state: TrainerState,
        control: TrainerControl,
        model: PreTrainedModel = None,
        tokenizer: PreTrainedTokenizer = None,
        **kwargs,
    ):
        self._log_metrics()

        temp_directory = tempfile.gettempdir()

        # Save and log the tokenizer:
        if tokenizer is not None:
            # Save tokenizer:
            tokenizer_dir = os.path.join(temp_directory, "tokenizer")
            tokenizer.save_pretrained(save_directory=tokenizer_dir)
            # Zip the tokenizer directory:
            tokenizer_zip = shutil.make_archive(
                base_name="tokenizer",
                format="zip",
                root_dir=tokenizer_dir,
            )
            # Log the zip file:
            self._artifacts["tokenizer"] = self._context.log_artifact(
                item="tokenizer", local_path=tokenizer_zip
            )

        # Save the model:
        model_dir = os.path.join(temp_directory, "model")
        model.save_pretrained(save_directory=model_dir)

        # Zip the model directory:
        shutil.make_archive(
            base_name="model",
            format="zip",
            root_dir=model_dir,
        )

        # Log the model:
        self._context.log_model(
            key="model",
            db_key=self._model_name,
            model_file="model.zip",
            tag=self._tag,
            framework="Hugging Face",
            labels=self._labels,
            extra_data={**self._artifacts, **self._extra_data},
        )

    def on_evaluate(
        self,
        args: TrainingArguments,
        state: TrainerState,
        control: TrainerControl,
        **kwargs,
    ):
        self._log_metrics()

        if self._is_training:
            return

        # TODO: Update the model object

    def _log_metrics(self):
        for metric_name, metric_scores in self._metric_scores.items():
            self._context.log_result(key=metric_name, value=metric_scores[-1])
            if len(metric_scores) > 1:
                self._log_metric_plot(name=metric_name, scores=metric_scores)
        self._context.commit(completed=False)

    def _log_metric_plot(self, name: str, scores: List[float]):
        # Initialize a plotly figure:
        metric_figure = go.Figure()

        # Add titles:
        metric_figure.update_layout(
            title=name.capitalize().replace("_", " "),
            xaxis_title="Samples",
            yaxis_title="Scores",
        )

        # Draw:
        metric_figure.add_trace(
            go.Scatter(x=np.arange(len(scores)), y=scores, mode="lines")
        )

        # Create the plotly artifact:
        artifact_name = f"{name}_plot"
        artifact = PlotlyArtifact(key=artifact_name, figure=metric_figure)
        self._artifacts[artifact_name] = self._context.log_artifact(artifact)