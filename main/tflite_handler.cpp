
#include "tflite_handler.h"

#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_log.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/schema/schema_generated.h"

#include "model_data.h"

#define TENSOR_ARENA_SIZE (4 * 1024)

namespace {
uint8_t tensor_arena[TENSOR_ARENA_SIZE];

tflite::MicroInterpreter* interpreter = nullptr;
const tflite::Model* model = nullptr;
TfLiteTensor* input = nullptr;
TfLiteTensor* output = nullptr;
}

const char* RISK_CLASSES[] = { "Good", "Medium", "Risky" };

extern "C" bool setup_tflite() {
    MicroPrintf("Setting up TensorFlow Lite model...");

    model = tflite::GetModel(wifi_model);
    if (model->version() != TFLITE_SCHEMA_VERSION) {
        MicroPrintf("Model provided is schema version %d not equal "
                    "to supported version %d.",
                    model->version(), TFLITE_SCHEMA_VERSION);
        return false;
    }

    static tflite::MicroMutableOpResolver<5> op_resolver;
    if (op_resolver.AddFullyConnected() != kTfLiteOk) return false;
    if (op_resolver.AddQuantize() != kTfLiteOk) return false;
    if (op_resolver.AddDequantize() != kTfLiteOk) return false;
    if (op_resolver.AddRelu() != kTfLiteOk) return false;
    if (op_resolver.AddSoftmax() != kTfLiteOk) return false;


    static tflite::MicroInterpreter static_interpreter(
        model, op_resolver, tensor_arena, TENSOR_ARENA_SIZE);
    interpreter = &static_interpreter;

    if (interpreter->AllocateTensors() != kTfLiteOk) {
        MicroPrintf("Failed to allocate tensors!");
        return false;
    }

    input = interpreter->input(0);
    output = interpreter->output(0);

    if (input->dims->data[1] != NUM_INPUTS || output->dims->data[1] != NUM_OUTPUTS) {
        MicroPrintf("Model input/output shape mismatch!");
        return false;
    }

    MicroPrintf("EloquentTinyML model initialized successfully.");
    return true;
}

extern "C" const char* classify_network_from_features(float auth, float rssi, float hidden) {
    if (!interpreter) {
        return "Not Ready";
    }

    input->data.f[0] = auth;
    input->data.f[1] = rssi;
    input->data.f[2] = hidden;

    if (interpreter->Invoke() != kTfLiteOk) {
        MicroPrintf("Invoke failed!");
        return "Error";
    }

    float good_score = output->data.f[0];
    float medium_score = output->data.f[1];
    float risky_score = output->data.f[2];

    int max_index = 0;
    float max_score = good_score;

    if (medium_score > max_score) {
        max_score = medium_score;
        max_index = 1;
    }
    if (risky_score > max_score) {
        max_score = risky_score;
        max_index = 2;
    }

    return RISK_CLASSES[max_index];
}