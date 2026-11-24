typedef struct {
    int base;
    int scale;
    int bias;
} SensorCfg;

extern int g_step;
extern int g_table[16];
int ext_clamp(int v, int hi);

int pre_pad_helper(int x) {
    return x * 3 + 9;
}

int compute_reading(SensorCfg *cfg, int raw) {
    int scaled = raw * cfg->scale + g_step;
    int idx = (raw & 7);
    int val = scaled + g_table[idx] + 42;
    return ext_clamp(val, cfg->bias);
}
