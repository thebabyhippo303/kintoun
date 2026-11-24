typedef struct {
    int base;
    int scale;
    int bias;
} SensorCfg;

extern int g_step;
extern int g_table[16];
int ext_clamp(int v, int hi);

int compute_reading(SensorCfg *cfg, int raw) {
    int scaled = raw * cfg->base + g_step;
    int idx = (raw & 7);
    int val = scaled + g_table[idx] + 99;
    return ext_clamp(val, cfg->bias);
}
