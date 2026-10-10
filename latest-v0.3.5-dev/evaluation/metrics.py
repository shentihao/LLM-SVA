def precision(tp, fp):
    return tp / (tp + fp) if tp + fp else 0.0


def recall(tp, fn):
    return tp / (tp + fn) if tp + fn else 0.0


def f1(tp, fp, fn):
    p = precision(tp, fp)
    r = recall(tp, fn)
    return 2 * p * r / (p + r) if p + r else 0.0


def false_positive_rate(fp, tn):
    return fp / (fp + tn) if fp + tn else 0.0
