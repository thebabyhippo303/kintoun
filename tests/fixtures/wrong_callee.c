typedef struct {
    int base;
    int scale;
    int bias;
} SensorCfg;

extern int g_step;
extern int g_table[16];
int ext_other(int v, int hi);

int compute_reading(SensorCfg *cfg, int raw) {
    int scaled = raw * cfg->scale + g_step;
    int idx = (raw & 7);
    int val = scaled + g_table[idx] + 42;
    return ext_other(val, cfg->bias);
}
