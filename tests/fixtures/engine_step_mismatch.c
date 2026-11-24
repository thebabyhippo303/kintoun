typedef struct {
    short gain;
    short offset;
    unsigned char mode;
    unsigned char shift;
    unsigned short mask;
    int accum;
    int peak;
} ChannelState;

extern int g_mix_bias;
extern const short g_curve_lut[16];
int mix_commit(ChannelState *ch, int total, int count);

int step_channel_block(ChannelState *ch, const short *samples, int count) {
    int total = g_mix_bias;
    int peak = ch->accum;
    int gain = ch->gain;
    int off = ch->offset;
    int i;

    for (i = 0; i < count; i++) {
        int s = samples[i];
        int v = ((s * gain) >> ch->shift) + off;
        if (ch->mode & 1) {
            v += g_curve_lut[s & 15];
        } else {
            v -= (s & ch->mask);
        }
        if (v > peak) {
            peak = v;
        }
        total += v;
    }
    ch->peak = peak;
    ch->accum = total;
    return mix_commit(ch, total + 96, count);
}
