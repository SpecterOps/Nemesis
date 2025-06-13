import { useNavigate } from 'react-router-dom';

export const useFileNavigation = () => {
  const navigate = useNavigate();

  return (finding) => {
    navigate(`/files/${finding.object_id}`, {
      state: {
        from: 'findings',
      }
    });
  };
};