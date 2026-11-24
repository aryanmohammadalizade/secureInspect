"""Optional industrial use case: linear extrapolation, not a trained AI model."""


def forecast(reading):
    years = reading["current_year"] - reading["previous_year"]
    rate = (reading["previous_mm"] - reading["current_mm"]) / years
    future = reading["current_mm"] - rate * 3
    return {"rate_mm_year": round(rate, 3), "forecast_mm": round(future, 3),
            "forecast_year": reading["current_year"] + 3, "threshold_mm": 6.0,
            "below_threshold": future < 6.0}


def plausibility(reading):
    old, new = reading["previous_mm"], reading["current_mm"]
    if not (1 <= old <= 20 and 1 <= new <= 20):
        return "Thickness outside the illustrative 1–20 mm range."
    if new - old > 0.3:
        return "Unexpected thickness increase (over 0.3 mm); review the sensor or repair history."
    if (old - new) / (reading["current_year"] - reading["previous_year"]) > 2:
        return "Apparent corrosion rate exceeds the illustrative 2 mm/year limit."
    return None
