interface StepperProps {
  steps: readonly string[];
  activeStep: number;
}

export function Stepper({ steps, activeStep }: StepperProps) {
  return (
    <ol aria-label="Setup progress" className="stepper">
      {steps.map((step, index) => (
        <li
          aria-current={index === activeStep ? "step" : undefined}
          className={index === activeStep ? "step active" : "step"}
          key={step}
        >
          <span className="step-circle">{index + 1}</span>
          <span className="step-label">{step}</span>
        </li>
      ))}
    </ol>
  );
}
